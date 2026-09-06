from __future__ import annotations

from collections import defaultdict

from .analyzer import build_graph
from .store import all_observations, list_actors
from .workflow import navigation_by_observation, workflow_checkpoints

STATEFUL_ACTIONS = {
    "accept", "approve", "verify", "invite", "promote", "demote", "remove", "delete",
    "revoke", "enable", "disable", "activate", "deactivate", "complete", "submit",
    "cancel", "archive", "restore", "create_or_action", "update", "login", "logout", "register",
}

REPLAY_ACTIONS = STATEFUL_ACTIONS - {"login", "logout", "register"}
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def _append_unique(hypotheses: list[dict], seen: set, key: tuple, item: dict) -> None:
    if key in seen:
        return
    seen.add(key)
    hypotheses.append(item)


def _ranked(hypotheses: list[dict]) -> list[dict]:
    return sorted(
        hypotheses,
        key=lambda item: (
            -int(item.get("priority_score") or 0),
            -CONFIDENCE_RANK.get(str(item.get("confidence") or "low"), 0),
            str(item.get("title") or ""),
        ),
    )


def transition_hypotheses(campaign_id: str, limit: int = 50) -> dict:
    observations = all_observations(campaign_id)
    graph = build_graph(campaign_id)

    hypotheses = []
    seen = set()

    by_id = {o["observation_id"]: o for o in observations}
    navigation = navigation_by_observation(observations)

    for change in graph.get("behavior_changes", []):
        if change.get("type") != "redirect_to_success":
            continue
        intermediate_ids = change.get("intermediate_observation_ids", [])
        if not intermediate_ids:
            continue

        intermediate = [by_id[obs_id] for obs_id in intermediate_ids if obs_id in by_id]
        checkpoint_records = workflow_checkpoints(intermediate)
        checkpoints = []
        for record in checkpoint_records:
            obs = record["observation"]
            checkpoints.append({
                "after_observation_id": obs["observation_id"],
                "after_action": obs["action"],
                "after_method": obs["method"],
                "after_path": obs["path"],
                "state_boundary_reasons": record["reasons"],
                "test_method": change["method"],
                "test_path": change["path"],
            })

        if not checkpoints:
            for obs in intermediate:
                nav = navigation.get(obs["observation_id"])
                if nav and nav.get("pure_navigation"):
                    continue
                checkpoints.append({
                    "after_observation_id": obs["observation_id"],
                    "after_action": obs["action"],
                    "after_method": obs["method"],
                    "after_path": obs["path"],
                    "state_boundary_reasons": ["workflow_observation"],
                    "test_method": change["method"],
                    "test_path": change["path"],
                })

        key = ("intermediate_access", change["actor_id"], change["method"], change["path"])
        _append_unique(hypotheses, seen, key, {
            "type": "intermediate_state_access",
            "confidence": "high",
            "priority_score": 100,
            "title": f"Re-test {change['method']} {change['path']} at observed workflow state boundaries",
            "actor_id": change["actor_id"],
            "method": change["method"],
            "path": change["path"],
            "evidence": [change["before"]["observation_id"], *intermediate_ids, change["after"]["observation_id"]],
            "workflow_span": {
                "before_observation_id": change["before"]["observation_id"],
                "after_observation_id": change["after"]["observation_id"],
                "intermediate_observation_ids": intermediate_ids,
            },
            "checkpoints": checkpoints,
            "why": (
                "The same resource changed from a redirect response to a successful response across an observed workflow span. "
                "FlowState identified passive state boundaries inside that span but has no evidence showing the earliest boundary "
                "at which access became allowed."
            ),
            "expected_safe_behavior": (
                "Access remains denied until every security-relevant prerequisite in the workflow has completed."
            ),
            "ranking_reason": "Access-gate change across a multi-step workflow with unresolved prerequisite boundary.",
            "manual_validation_required": True,
        })

        # Turn the whole workflow span into concrete destination-focused checks. A checkpoint is only useful
        # when at least one later state boundary still remains; otherwise it merely restates the normal flow.
        for checkpoint_index, checkpoint in enumerate(checkpoints[:-1]):
            remaining = checkpoints[checkpoint_index + 1:]
            if not remaining:
                continue
            checkpoint_id = checkpoint["after_observation_id"]
            remaining_ids = [item["after_observation_id"] for item in remaining]
            key = (
                "workflow_checkpoint_access",
                change["actor_id"],
                checkpoint_id,
                change["method"],
                change["path"],
            )
            _append_unique(hypotheses, seen, key, {
                "type": "workflow_checkpoint_access",
                "confidence": "high",
                "priority_score": max(80, 95 - checkpoint_index * 5),
                "title": (
                    f"Test {change['method']} {change['path']} immediately after "
                    f"{checkpoint['after_method']} {checkpoint['after_path']}"
                ),
                "actor_id": change["actor_id"],
                "method": change["method"],
                "path": change["path"],
                "checkpoint": checkpoint,
                "remaining_prerequisite_observation_ids": remaining_ids,
                "evidence": [
                    change["before"]["observation_id"],
                    checkpoint_id,
                    *remaining_ids,
                    change["after"]["observation_id"],
                ],
                "why": (
                    "The destination was denied before the workflow and successful after it. This checkpoint occurs before one or "
                    "more later passive state boundaries, so testing the destination here can determine whether downstream "
                    "prerequisites are actually enforced."
                ),
                "expected_safe_behavior": (
                    "The destination remains denied if any later security-relevant prerequisite is mandatory."
                ),
                "ranking_reason": "Destination-focused prerequisite test derived from the complete observed workflow span.",
                "manual_validation_required": True,
            })

    by_actor: dict[str, list[dict]] = defaultdict(list)
    for obs in observations:
        by_actor[obs["actor_id"]].append(obs)

    for actor_id, actor_obs in by_actor.items():
        for left, middle, right in zip(actor_obs, actor_obs[1:], actor_obs[2:]):
            if middle["action"] not in STATEFUL_ACTIONS:
                continue
            if middle["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
                continue
            if middle.get("status") is None or middle["status"] >= 400:
                continue
            if right["path"] == middle["path"] and right["method"] == middle["method"]:
                continue

            # Redirect-follow GET/HEAD requests are transport/navigation edges, not useful destinations for a
            # local three-request skip hypothesis. Whole-span access hypotheses above retain any meaningful
            # state boundary carried by that navigation request.
            if right["observation_id"] in navigation:
                continue

            key = ("skip", actor_id, middle["observation_id"], right["method"], right["path"])
            _append_unique(hypotheses, seen, key, {
                "type": "skip_step",
                "confidence": "medium",
                "priority_score": 50,
                "title": f"Test whether {middle['method']} {middle['path']} can be skipped before {right['method']} {right['path']}",
                "actor_id": actor_id,
                "precondition_observation_id": left["observation_id"],
                "skipped_observation_id": middle["observation_id"],
                "destination_observation_id": right["observation_id"],
                "destination": {"method": right["method"], "path": right["path"]},
                "evidence": [left["observation_id"], middle["observation_id"], right["observation_id"]],
                "why": (
                    "A successful state-changing step sits between two observed workflow states. FlowState has not observed whether the "
                    "destination remains protected when that middle step is omitted."
                ),
                "expected_safe_behavior": "The destination rejects or redirects the actor if the skipped step is a required prerequisite.",
                "ranking_reason": "Local adjacency hypothesis without a stronger destination-wide access-gate signal.",
                "manual_validation_required": True,
            })

    for obs in observations:
        if obs["action"] not in REPLAY_ACTIONS:
            continue
        if obs["status"] is None or obs["status"] >= 400:
            continue
        key = ("replay", obs["method"], obs["path"], obs["actor_id"])
        _append_unique(hypotheses, seen, key, {
            "type": "replay_transition",
            "confidence": "medium",
            "priority_score": 30,
            "title": f"Re-test whether {obs['action']} is safely one-time or idempotent",
            "actor_id": obs["actor_id"],
            "method": obs["method"],
            "path": obs["path"],
            "evidence": [obs["observation_id"]],
            "why": "A state-changing request succeeded, but FlowState has no proof that repeating the same transition is rejected or safely idempotent.",
            "expected_safe_behavior": "The server rejects an invalid repeated transition or returns a harmless idempotent result.",
            "ranking_reason": "Useful generic replay question, but lower signal than an observed access-gate change.",
            "manual_validation_required": True,
        })

    for t in graph["transitions"]:
        if t["type"] == "session_rotation":
            continue
        key = ("state", t["type"], t["field"], t["before"], t["after"], t["path"])
        _append_unique(hypotheses, seen, key, {
            "type": "state_transition",
            "transition_type": t["type"],
            "confidence": "medium",
            "priority_score": 40,
            "title": f"Validate forbidden transitions around {t['field']}",
            "actor_id": t["actor_id"],
            "path": t["path"],
            "evidence": [t["observation_id"]],
            "why": "A concrete state transition was observed. Adjacent, skipped, reversed, or repeated transitions remain unknown.",
            "ranking_reason": "Concrete state transition, but no direct access-gate change was established.",
            "manual_validation_required": True,
        })

    ranked = _ranked(hypotheses)
    return {"campaign_id": campaign_id, "hypotheses": ranked[:max(1, min(limit, 200))]}


def actor_swap_hypotheses(campaign_id: str, limit: int = 50) -> dict:
    observations = all_observations(campaign_id)
    actors = list_actors(campaign_id)
    actor_ids = [a["actor_id"] for a in actors]

    by_endpoint = defaultdict(list)
    for obs in observations:
        if obs["action"] not in STATEFUL_ACTIONS:
            continue
        by_endpoint[(obs["method"], obs["path"], obs["action"])].append(obs)

    hypotheses = []
    seen = set()

    for (method, path, action), obs_list in by_endpoint.items():
        successful_actors = {
            o["actor_id"] for o in obs_list
            if o["status"] is not None and o["status"] < 400
        }
        if not successful_actors:
            continue

        for source_actor in sorted(successful_actors):
            for candidate in actor_ids:
                if candidate == source_actor:
                    continue
                key = (method, path, action, source_actor, candidate)
                if key in seen:
                    continue
                seen.add(key)

                evidence = [o["observation_id"] for o in obs_list if o["actor_id"] == source_actor][:5]
                hypotheses.append({
                    "type": "actor_swap",
                    "confidence": "low",
                    "title": f"Compare {candidate} against {source_actor} for {action}",
                    "method": method,
                    "path": path,
                    "source_actor": source_actor,
                    "candidate_actor": candidate,
                    "evidence": evidence,
                    "why": "This state-changing operation succeeded for one registered actor. Authorization behavior for another registered actor is not established by current evidence.",
                    "manual_validation_required": True,
                })

    return {"campaign_id": campaign_id, "hypotheses": hypotheses[:max(1, min(limit, 200))]}
