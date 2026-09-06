from __future__ import annotations

import hashlib
import json
import re
import secrets
from urllib.parse import urlsplit

from .sanitize import sanitize_path
from .store import FlowStateError, _campaign_dir, _read_json, _write_json, audit, get_campaign, now_iso

VALIDATION_OUTCOMES = {"supported", "falsified", "inconclusive"}
HYPOTHESIS_ID_RE = re.compile(r"^hyp-[0-9a-f]{16}$")
METHOD_RE = re.compile(r"^[A-Z]{1,16}$")
SENSITIVE_NOTE_RE = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|session|csrf|password|passwd|pwd|"
    r"token|secret|api[_-]?key|x-api-key)\s*[:=]\s*([^\s,;]+)"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+[^\s,;]+")


def _hypothesis_identity_payload(hypothesis: dict) -> dict:
    """Return a semantic, ranking-independent identity for one generated hypothesis."""
    checkpoint = hypothesis.get("checkpoint") or {}
    workflow_span = hypothesis.get("workflow_span") or {}
    destination = hypothesis.get("destination") or {}
    evidence = hypothesis.get("evidence") or []

    payload = {
        "type": hypothesis.get("type"),
        "actor_id": hypothesis.get("actor_id"),
        "source_actor": hypothesis.get("source_actor"),
        "candidate_actor": hypothesis.get("candidate_actor"),
        "method": hypothesis.get("method"),
        "path": hypothesis.get("path"),
        "action": hypothesis.get("action"),
        "transition_type": hypothesis.get("transition_type"),
        "precondition_observation_id": hypothesis.get("precondition_observation_id"),
        "skipped_observation_id": hypothesis.get("skipped_observation_id"),
        "destination_observation_id": hypothesis.get("destination_observation_id"),
        "checkpoint_observation_id": checkpoint.get("after_observation_id"),
        "workflow_before_observation_id": workflow_span.get("before_observation_id"),
        "workflow_after_observation_id": workflow_span.get("after_observation_id"),
        "destination_method": destination.get("method"),
        "destination_path": destination.get("path"),
    }

    # Some generic hypothesis classes intentionally expose fewer semantic fields. The first evidence
    # observation is a stable campaign-local anchor that prevents otherwise identical records colliding.
    if not any(value is not None for key, value in payload.items() if key != "type") and evidence:
        payload["evidence_anchor"] = evidence[0]
    elif hypothesis.get("type") == "state_transition" and evidence:
        payload["evidence_anchor"] = evidence[0]

    return payload


def hypothesis_id(hypothesis: dict) -> str:
    payload = _hypothesis_identity_payload(hypothesis)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "hyp-" + hashlib.sha256(encoded).hexdigest()[:16]


def _validations_path(campaign_id: str):
    return _campaign_dir(campaign_id) / "validations.json"


def list_hypothesis_validations(
    campaign_id: str,
    hypothesis_id_value: str | None = None,
    limit: int = 200,
) -> list[dict]:
    get_campaign(campaign_id)
    records = _read_json(_validations_path(campaign_id), []) or []
    if hypothesis_id_value:
        if not HYPOTHESIS_ID_RE.fullmatch(str(hypothesis_id_value)):
            raise FlowStateError("Invalid hypothesis_id")
        records = [record for record in records if record.get("hypothesis_id") == hypothesis_id_value]
    records.sort(key=lambda item: str(item.get("recorded_at") or ""))
    limit = max(1, min(int(limit), 1000))
    return records[-limit:]


def annotate_hypotheses(campaign_id: str, hypotheses: list[dict]) -> list[dict]:
    """Attach stable IDs and the latest persisted manual-validation state to generated hypotheses."""
    records = list_hypothesis_validations(campaign_id, limit=1000)
    by_hypothesis: dict[str, list[dict]] = {}
    for record in records:
        by_hypothesis.setdefault(str(record.get("hypothesis_id") or ""), []).append(record)

    result = []
    for hypothesis in hypotheses:
        item = dict(hypothesis)
        hid = hypothesis_id(item)
        history = by_hypothesis.get(hid, [])
        latest = history[-1] if history else None
        item["hypothesis_id"] = hid
        item["validation_status"] = latest.get("outcome") if latest else "untested"
        item["validation_count"] = len(history)
        item["latest_validation"] = latest
        result.append(item)
    return result


def _sanitize_validation_path(value: str | None, label: str, allow_none: bool = False) -> str | None:
    if value is None:
        if allow_none:
            return None
        raise FlowStateError(f"{label} is required")
    raw = str(value).strip()
    if not raw:
        if allow_none:
            return None
        raise FlowStateError(f"{label} is required")
    parsed = urlsplit(raw)
    if parsed.scheme or parsed.netloc:
        raise FlowStateError(f"{label} must be a path, not a URL")
    if not parsed.path.startswith("/"):
        raise FlowStateError(f"{label} must start with /")
    return sanitize_path(parsed.path or "/")


def _sanitize_note(value: str | None) -> str:
    if not value:
        return ""
    text = str(value).replace("\r", " ").replace("\n", " ")[:1000]
    text = SENSITIVE_NOTE_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = BEARER_RE.sub("Bearer [REDACTED]", text)
    return text


def record_hypothesis_validation(
    campaign_id: str,
    hypothesis_id_value: str,
    outcome: str,
    test_method: str,
    test_path: str,
    observed_status: int | None = None,
    observed_redirect_path: str | None = None,
    notes: str | None = None,
    known_hypothesis_ids: set[str] | None = None,
) -> dict:
    """Persist one structured, sanitized manual-validation result without sending traffic."""
    get_campaign(campaign_id)
    hid = str(hypothesis_id_value)
    if not HYPOTHESIS_ID_RE.fullmatch(hid):
        raise FlowStateError("Invalid hypothesis_id")
    if known_hypothesis_ids is not None and hid not in known_hypothesis_ids:
        raise FlowStateError("hypothesis_id is not currently generated for this campaign")

    normalized_outcome = str(outcome).strip().lower()
    if normalized_outcome not in VALIDATION_OUTCOMES:
        raise FlowStateError("outcome must be one of: supported, falsified, inconclusive")

    method = str(test_method).strip().upper()
    if not METHOD_RE.fullmatch(method):
        raise FlowStateError("Invalid test_method")
    path = _sanitize_validation_path(test_path, "test_path")
    redirect_path = _sanitize_validation_path(
        observed_redirect_path,
        "observed_redirect_path",
        allow_none=True,
    )

    status = None
    if observed_status is not None:
        try:
            status = int(observed_status)
        except (TypeError, ValueError) as exc:
            raise FlowStateError("observed_status must be an integer") from exc
        if not 100 <= status <= 599:
            raise FlowStateError("observed_status must be between 100 and 599")

    record = {
        "validation_id": f"val-{secrets.token_hex(6)}",
        "hypothesis_id": hid,
        "outcome": normalized_outcome,
        "source": "manual",
        "test": {
            "method": method,
            "path": path,
        },
        "observed": {
            "status": status,
            "redirect_path": redirect_path,
        },
        "notes": _sanitize_note(notes),
        "recorded_at": now_iso(),
    }

    path_obj = _validations_path(campaign_id)
    records = _read_json(path_obj, []) or []
    records.append(record)
    _write_json(path_obj, records)
    audit(
        campaign_id,
        "hypothesis_validation_recorded",
        {
            "validation_id": record["validation_id"],
            "hypothesis_id": hid,
            "outcome": normalized_outcome,
            "test_method": method,
            "test_path": path,
            "observed_status": status,
        },
    )
    return record
