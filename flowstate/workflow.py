from __future__ import annotations

from collections import defaultdict

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _body_has_state(summary: dict | None) -> bool:
    if not isinstance(summary, dict):
        return False
    return bool(summary.get("state_fields"))


def has_state_evidence(observation: dict) -> bool:
    """Return whether one observation carries passive evidence of an application-state boundary."""
    session = observation.get("session") or {}
    if session.get("session_changed"):
        return True

    method = str(observation.get("method") or "").upper()
    status = observation.get("status")
    if method in STATE_CHANGING_METHODS and isinstance(status, int) and status < 400:
        return True

    request_body = ((observation.get("request") or {}).get("body") or {})
    response_body = ((observation.get("response") or {}).get("body") or {})
    return _body_has_state(request_body) or _body_has_state(response_body)


def state_boundary_reasons(observation: dict) -> list[str]:
    reasons: list[str] = []
    session = observation.get("session") or {}
    if session.get("session_changed"):
        reasons.append("session_rotation")

    method = str(observation.get("method") or "").upper()
    status = observation.get("status")
    if method in STATE_CHANGING_METHODS and isinstance(status, int) and status < 400:
        reasons.append("successful_state_change")

    request_body = ((observation.get("request") or {}).get("body") or {})
    response_body = ((observation.get("response") or {}).get("body") or {})
    if _body_has_state(request_body) or _body_has_state(response_body):
        reasons.append("state_field_evidence")

    return reasons


def redirect_matches(left: dict, right: dict) -> bool:
    redirect = ((left.get("response") or {}).get("redirect") or {})
    if not redirect or not redirect.get("same_target"):
        return False
    if redirect.get("path") != right.get("path"):
        return False
    return sorted(redirect.get("query_parameter_names") or []) == sorted(
        right.get("query_parameter_names") or []
    )


def navigation_evidence(observations: list[dict]) -> list[dict]:
    """Identify redirect-follow navigation without relying on path names or target-specific rules."""
    by_actor: dict[str, list[dict]] = defaultdict(list)
    for observation in observations:
        by_actor[str(observation.get("actor_id") or "")].append(observation)

    result: list[dict] = []
    for actor_id, actor_observations in by_actor.items():
        for left, right in zip(actor_observations, actor_observations[1:]):
            if str(right.get("method") or "").upper() not in {"GET", "HEAD"}:
                continue
            if not redirect_matches(left, right):
                continue

            boundary_reasons = state_boundary_reasons(right)
            result.append(
                {
                    "observation_id": right.get("observation_id"),
                    "actor_id": actor_id,
                    "method": right.get("method"),
                    "path": right.get("path"),
                    "source_observation_id": left.get("observation_id"),
                    "reason": "redirect_follow",
                    "state_boundary": bool(boundary_reasons),
                    "state_boundary_reasons": boundary_reasons,
                    "pure_navigation": not bool(boundary_reasons),
                }
            )
    return result


def navigation_by_observation(observations: list[dict]) -> dict[str, dict]:
    return {
        str(item["observation_id"]): item
        for item in navigation_evidence(observations)
        if item.get("observation_id")
    }


def workflow_checkpoints(intermediate_observations: list[dict]) -> list[dict]:
    """Return intermediate observations backed by passive evidence of a state boundary."""
    checkpoints = []
    for observation in intermediate_observations:
        reasons = state_boundary_reasons(observation)
        if not reasons:
            continue
        checkpoints.append(
            {
                "observation": observation,
                "reasons": reasons,
            }
        )
    return checkpoints
