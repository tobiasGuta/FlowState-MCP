from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit

from defusedxml import ElementTree as DET

from .config import limits
from .sanitize import (
    cookie_fingerprints,
    sanitize_headers,
    sanitize_path,
    sanitize_query,
    sanitize_redirect,
    set_cookie_fingerprints,
    summarize_body,
)
from .store import FlowStateError, actor_exists, get_campaign, now_iso, save_observations


def _bounded_read(path: Path, max_bytes: int) -> bytes:
    if not path.exists() or not path.is_file():
        raise FlowStateError("Import file not found")
    size = path.stat().st_size
    if size > max_bytes:
        raise FlowStateError(f"Import exceeds maximum size of {max_bytes} bytes")
    return path.read_bytes()


def _validate_actor(campaign_id: str, actor_id: str) -> None:
    if not actor_exists(campaign_id, actor_id):
        raise FlowStateError("actor_id is not registered in this campaign")


def _target_ok(campaign: dict, url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host == campaign["target_host"] or host.endswith("." + campaign["target_host"])


def infer_action(method: str, path: str) -> str:
    method = method.upper()
    segments = [s for s in path.split("/") if s]
    last = segments[-1].lower() if segments else ""
    verbs = {
        "accept": "accept",
        "approve": "approve",
        "verify": "verify",
        "invite": "invite",
        "promote": "promote",
        "demote": "demote",
        "remove": "remove",
        "delete": "delete",
        "revoke": "revoke",
        "enable": "enable",
        "disable": "disable",
        "activate": "activate",
        "deactivate": "deactivate",
        "complete": "complete",
        "submit": "submit",
        "cancel": "cancel",
        "archive": "archive",
        "restore": "restore",
        "login": "login",
        "logout": "logout",
        "register": "register",
        "signup": "register",
    }
    if last in verbs:
        return verbs[last]
    if method == "POST":
        return "create_or_action"
    if method in {"PUT", "PATCH"}:
        return "update"
    if method == "DELETE":
        return "delete"
    return "read"


def _parse_observed_time(value: str | None) -> tuple[str | None, datetime | None]:
    raw = (value or "").strip()
    if not raw:
        return None, None

    dt: datetime | None = None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        try:
            dt = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            dt = None

    if dt is None:
        return None, None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.isoformat(), dt


def _session_summary(req_headers, resp_headers) -> dict:
    req = cookie_fingerprints(req_headers)
    resp = set_cookie_fingerprints(resp_headers)
    before = req.get("session")
    after = resp.get("session")
    return {
        "request_cookie_fingerprints": req,
        "response_cookie_fingerprints": resp,
        "request_session_fingerprint": before,
        "response_session_fingerprint": after,
        "session_changed": bool(before and after and before != after),
    }


def _observation(
    actor_id: str,
    method: str,
    url: str,
    req_headers,
    req_body,
    status,
    resp_headers,
    resp_body,
    source: str,
    source_ref: str,
    campaign: dict,
    observed_at: str | None = None,
) -> dict:
    clean_url, query_names = sanitize_query(url)
    path = sanitize_path(urlsplit(url).path or "/")
    req_h = sanitize_headers(req_headers)
    resp_h = sanitize_headers(resp_headers)

    req_ct = next((v for k, v in req_h.items() if k.lower() == "content-type"), "")
    resp_ct = next((v for k, v in resp_h.items() if k.lower() == "content-type"), "")

    lim = limits()
    req_summary = summarize_body(req_body, req_ct, lim["max_body_bytes"])
    resp_summary = summarize_body(resp_body, resp_ct, lim["max_response_bytes"])

    return {
        "observation_schema_version": 2,
        "observation_id": f"obs-{source_ref}",
        "timestamp": observed_at or now_iso(),
        "imported_at": now_iso(),
        "actor_id": actor_id,
        "method": method.upper(),
        "url": clean_url,
        "path": path,
        "query_parameter_names": query_names,
        "status": int(status) if str(status).isdigit() else None,
        "action": infer_action(method, path),
        "request": {
            "header_names": sorted(req_h.keys()),
            "headers": req_h,
            "body": req_summary,
        },
        "response": {
            "header_names": sorted(resp_h.keys()),
            "headers": resp_h,
            "body": resp_summary,
            "redirect": sanitize_redirect(resp_headers, campaign["target_host"]),
        },
        "session": _session_summary(req_headers, resp_headers),
        "source": source,
        "source_ref": source_ref,
    }


def _finalize_chronology(records: list[tuple[datetime | None, int, dict]]) -> tuple[list[dict], int]:
    max_dt = datetime.max.replace(tzinfo=timezone.utc)
    timestamped = sum(1 for dt, _idx, _obs in records if dt is not None)
    records.sort(key=lambda item: (item[0] or max_dt, item[1]))
    observations = []
    for sequence_index, (_dt, _original_index, obs) in enumerate(records, start=1):
        obs["sequence_index"] = sequence_index
        observations.append(obs)
    return observations, timestamped


def import_har(campaign_id: str, actor_id: str, path: str) -> dict:
    _validate_actor(campaign_id, actor_id)
    campaign = get_campaign(campaign_id)
    raw = _bounded_read(Path(path).resolve(), limits()["max_import_bytes"])
    try:
        har = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise FlowStateError(f"Invalid HAR JSON: {exc}") from exc

    entries = (((har or {}).get("log") or {}).get("entries") or [])
    records: list[tuple[datetime | None, int, dict]] = []
    skipped_out_of_target = 0

    for idx, entry in enumerate(entries):
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        url = str(req.get("url") or "")
        if not _target_ok(campaign, url):
            skipped_out_of_target += 1
            continue

        req_body = ((req.get("postData") or {}).get("text"))
        resp_body = ((resp.get("content") or {}).get("text"))
        if (resp.get("content") or {}).get("encoding") == "base64" and isinstance(resp_body, str):
            try:
                resp_body = base64.b64decode(resp_body)
            except Exception:
                resp_body = None

        observed_at, parsed_dt = _parse_observed_time(entry.get("startedDateTime"))
        obs = _observation(
            actor_id,
            str(req.get("method") or "GET"),
            url,
            req.get("headers") or [],
            req_body,
            resp.get("status"),
            resp.get("headers") or [],
            resp_body,
            "har",
            str(idx + 1),
            campaign,
            observed_at=observed_at,
        )
        records.append((parsed_dt, idx, obs))

    observations, timestamped = _finalize_chronology(records)
    saved = save_observations(campaign_id, observations, limits()["max_observations"])
    return {
        "ok": True,
        "source": "har",
        "actor_id": actor_id,
        "parsed": len(observations),
        "skipped_out_of_target": skipped_out_of_target,
        "chronology_sorted": True,
        "timestamped": timestamped,
        **saved,
    }


def _parse_raw_http_request(raw: str) -> tuple[str, str, dict, str]:
    head, separator, body = raw.partition("\r\n\r\n")
    if not separator:
        head, separator, body = raw.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        return "GET", "/", {}, body
    first = lines[0].split()
    method = first[0] if first else "GET"
    target = first[1] if len(first) > 1 else "/"
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return method, target, headers, body


def _parse_raw_http_response(raw: str) -> tuple[int | None, dict, str]:
    head, separator, body = raw.partition("\r\n\r\n")
    if not separator:
        head, separator, body = raw.partition("\n\n")
    lines = head.splitlines()
    status = None
    if lines:
        parts = lines[0].split()
        if len(parts) > 1 and parts[1].isdigit():
            status = int(parts[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return status, headers, body


def import_burp_xml(campaign_id: str, actor_id: str, path: str) -> dict:
    _validate_actor(campaign_id, actor_id)
    campaign = get_campaign(campaign_id)
    raw = _bounded_read(Path(path).resolve(), limits()["max_import_bytes"])
    try:
        root = DET.fromstring(raw)
    except Exception as exc:
        raise FlowStateError(f"Invalid Burp XML: {exc}") from exc

    records: list[tuple[datetime | None, int, dict]] = []
    skipped_out_of_target = 0

    for idx, item in enumerate(root.findall(".//item")):
        url = (item.findtext("url") or "").strip()
        if not _target_ok(campaign, url):
            skipped_out_of_target += 1
            continue

        req_node = item.find("request")
        resp_node = item.find("response")

        req_raw = ""
        if req_node is not None and req_node.text:
            req_raw = req_node.text
            if req_node.attrib.get("base64", "").lower() == "true":
                try:
                    req_raw = base64.b64decode(req_raw).decode("utf-8", errors="replace")
                except Exception:
                    req_raw = ""

        resp_raw = ""
        if resp_node is not None and resp_node.text:
            resp_raw = resp_node.text
            if resp_node.attrib.get("base64", "").lower() == "true":
                try:
                    resp_raw = base64.b64decode(resp_raw).decode("utf-8", errors="replace")
                except Exception:
                    resp_raw = ""

        method, _target, req_headers, req_body = _parse_raw_http_request(req_raw)
        status, resp_headers, resp_body = _parse_raw_http_response(resp_raw)
        observed_at, parsed_dt = _parse_observed_time(item.findtext("time"))

        obs = _observation(
            actor_id,
            method,
            url,
            req_headers,
            req_body,
            status,
            resp_headers,
            resp_body,
            "burp_xml",
            str(idx + 1),
            campaign,
            observed_at=observed_at,
        )
        records.append((parsed_dt, idx, obs))

    observations, timestamped = _finalize_chronology(records)
    saved = save_observations(campaign_id, observations, limits()["max_observations"])
    return {
        "ok": True,
        "source": "burp_xml",
        "actor_id": actor_id,
        "parsed": len(observations),
        "skipped_out_of_target": skipped_out_of_target,
        "chronology_sorted": True,
        "timestamped": timestamped,
        **saved,
    }
