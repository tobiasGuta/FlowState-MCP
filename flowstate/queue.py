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


def _workflow_key(hypothesis: dict) -> tuple[str, str, str]:
    return (
        str(hypothesis.get("actor_id") or ""),
        str(hypothesis.get("method") or ""),
        str(hypothesis.get("path") or ""),
    )


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

    queue: list[dict] = []
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
            else "No validation result has resolved this hypothesis yet."
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

    bounded_limit = max(1, min(int(limit), 200))
    selected = queue[:bounded_limit]
    return {
        "campaign_id": campaign_id,
        "queue": selected,
        "queue_count": len(selected),
        "total_actionable_count": len(queue),
        "validation_status_counts": status_counts,
        "excluded_resolved_count": excluded_resolved,
        "suppressed_planning_count": suppressed_planning,
        "excluded_inconclusive_count": excluded_inconclusive,
        "include_inconclusive": bool(include_inconclusive),
    }
