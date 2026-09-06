from __future__ import annotations

from .validation import annotate_hypotheses

RESOLVED_STATUSES = {"supported", "falsified"}
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
CONFIDENCE_FALLBACK_PRIORITY = {"high": 60, "medium": 40, "low": 20}
INCONCLUSIVE_PRIORITY_PENALTY = 15


def _base_priority(hypothesis: dict) -> int:
    raw = hypothesis.get("priority_score")
    if raw is not None:
        try:
            return max(0, int(raw))
        except (TypeError, ValueError):
            pass
    return CONFIDENCE_FALLBACK_PRIORITY.get(str(hypothesis.get("confidence") or "low"), 20)


def _destination_key(hypothesis: dict) -> tuple[str, str, str]:
    """Return actor + destination method/path without relying on route names."""
    destination = hypothesis.get("destination") or {}
    method = hypothesis.get("method") or destination.get("method") or ""
    path = hypothesis.get("path") or destination.get("path") or ""
    return (
        str(hypothesis.get("actor_id") or ""),
        str(method),
        str(path),
    )


def _workflow_key(hypothesis: dict) -> tuple[str, str, str]:
    return _destination_key(hypothesis)


def _supported_checkpoint_sources(annotated: list[dict]) -> list[dict]:
    """Return directly supported checkpoint-access hypotheses that can dominate later workflow questions."""
    sources = [
        hypothesis
        for hypothesis in annotated
        if hypothesis.get("type") == "workflow_checkpoint_access"
        and hypothesis.get("validation_status") == "supported"
        and (hypothesis.get("checkpoint") or {}).get("after_observation_id")
    ]
    sources.sort(
        key=lambda item: (
            -len(item.get("remaining_prerequisite_observation_ids") or []),
            -_base_priority(item),
            str(item.get("hypothesis_id") or ""),
        )
    )
    return sources


def _subsumption_for(hypothesis: dict, supported_sources: list[dict]) -> dict | None:
    """Return safe queue-only dominance evidence for a hypothesis, if any.

    A supported checkpoint-access test proves the destination was already reachable at that checkpoint.
    Therefore later checkpoint-access questions for the same actor/destination, and skip-step questions
    about prerequisites that occurred after that checkpoint, no longer add information about the earliest
    access boundary. This does not change the target hypothesis's persisted validation status.
    """
    if hypothesis.get("validation_status") in RESOLVED_STATUSES:
        return None

    hypothesis_type = hypothesis.get("type")
    if hypothesis_type not in {"workflow_checkpoint_access", "skip_step"}:
        return None

    target_destination = _destination_key(hypothesis)
    if not all(target_destination):
        return None

    if hypothesis_type == "workflow_checkpoint_access":
        target_observation_id = (hypothesis.get("checkpoint") or {}).get("after_observation_id")
        relation = "later_checkpoint"
    else:
        target_observation_id = hypothesis.get("skipped_observation_id")
        relation = "later_prerequisite"

    if not target_observation_id:
        return None

    for source in supported_sources:
        if source.get("hypothesis_id") == hypothesis.get("hypothesis_id"):
            continue
        if _destination_key(source) != target_destination:
            continue

        remaining_ids = set(source.get("remaining_prerequisite_observation_ids") or [])
        if target_observation_id not in remaining_ids:
            continue

        source_checkpoint = source.get("checkpoint") or {}
        return {
            "queue_status": "subsumed",
            "subsumed_by": source.get("hypothesis_id"),
            "subsumption_relation": relation,
            "subsumption_evidence": {
                "supported_checkpoint_observation_id": source_checkpoint.get("after_observation_id"),
                "covered_observation_id": target_observation_id,
                "destination": {
                    "actor_id": target_destination[0],
                    "method": target_destination[1],
                    "path": target_destination[2],
                },
            },
            "queue_reason": (
                "A directly supported earlier checkpoint already showed this destination was reachable before "
                "the covered workflow step. Keep this hypothesis as untested history, but do not spend another "
                "validation request on the same earliest-access question."
            ),
        }

    return None


def build_hypothesis_queue(
    campaign_id: str,
    hypotheses: list[dict],
    limit: int = 20,
    include_inconclusive: bool = True,
) -> dict:
    """Return the highest-value unresolved hypotheses without changing their persisted validation state."""
    annotated = annotate_hypotheses(campaign_id, hypotheses)

    status_counts = {
        "untested": 0,
        "inconclusive": 0,
        "supported": 0,
        "falsified": 0,
    }
    for hypothesis in annotated:
        status = str(hypothesis.get("validation_status") or "untested")
        status_counts[status] = status_counts.get(status, 0) + 1

    # intermediate_state_access is an umbrella/planning hypothesis. When concrete checkpoint-access
    # hypotheses exist for the same actor and destination, keep the umbrella visible in normal hypothesis
    # output but do not let it compete with its concrete children in the "what should I test next?" queue.
    concrete_workflow_keys = {
        _workflow_key(hypothesis)
        for hypothesis in annotated
        if hypothesis.get("type") == "workflow_checkpoint_access"
    }
    supported_sources = _supported_checkpoint_sources(annotated)

    queue: list[dict] = []
    subsumed: list[dict] = []
    suppressed_planning = 0
    excluded_resolved = 0
    excluded_inconclusive = 0

    for hypothesis in annotated:
        status = str(hypothesis.get("validation_status") or "untested")

        if status in RESOLVED_STATUSES:
            excluded_resolved += 1
            continue

        if (
            hypothesis.get("type") == "intermediate_state_access"
            and _workflow_key(hypothesis) in concrete_workflow_keys
        ):
            suppressed_planning += 1
            continue

        dominance = _subsumption_for(hypothesis, supported_sources)
        if dominance:
            item = dict(hypothesis)
            item.update(dominance)
            item["base_priority_score"] = _base_priority(item)
            item["queue_priority_score"] = 0
            subsumed.append(item)
            continue

        if status == "inconclusive" and not include_inconclusive:
            excluded_inconclusive += 1
            continue

        item = dict(hypothesis)
        base_priority = _base_priority(item)
        penalty = INCONCLUSIVE_PRIORITY_PENALTY if status == "inconclusive" else 0
        item["base_priority_score"] = base_priority
        item["queue_priority_score"] = max(0, base_priority - penalty)
        item["queue_status"] = "retry_inconclusive" if status == "inconclusive" else "ready"
        item["queue_reason"] = (
            "Prior validation was inconclusive, so this remains actionable with a small retry penalty."
            if status == "inconclusive"
            else "No validation result has resolved or subsumed this hypothesis yet."
        )
        queue.append(item)

    queue.sort(
        key=lambda item: (
            -int(item.get("queue_priority_score") or 0),
            0 if item.get("validation_status") == "untested" else 1,
            -CONFIDENCE_RANK.get(str(item.get("confidence") or "low"), 0),
            str(item.get("title") or ""),
        )
    )
    subsumed.sort(
        key=lambda item: (
            -int(item.get("base_priority_score") or 0),
            str(item.get("title") or ""),
        )
    )

    bounded_limit = max(1, min(int(limit), 200))
    selected = queue[:bounded_limit]
    return {
        "campaign_id": campaign_id,
        "queue": selected,
        "queue_count": len(selected),
        "total_actionable_count": len(queue),
        "subsumed": subsumed,
        "subsumed_count": len(subsumed),
        "validation_status_counts": status_counts,
        "excluded_resolved_count": excluded_resolved,
        "suppressed_planning_count": suppressed_planning,
        "excluded_inconclusive_count": excluded_inconclusive,
        "include_inconclusive": bool(include_inconclusive),
    }
