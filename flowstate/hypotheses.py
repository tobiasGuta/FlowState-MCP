from __future__ import annotations

from collections import defaultdict

from .analyzer import build_graph
from .store import all_observations, list_actors

STATEFUL_ACTIONS = {
    "accept", "approve", "verify", "invite", "promote", "demote", "remove", "delete",
    "revoke", "enable", "disable", "activate", "deactivate", "complete", "submit",
    "cancel", "archive", "restore", "create_or_action", "update", "login", "logout", "register",
}

REPLAY_ACTIONS = STATEFUL_ACTIONS - {"login", "logout", "register"}


def _append_unique(hypotheses: list[dict], seen: set, key: tuple, item: dict) -> None:
    if key in seen:
        return
    seen.add(key)
    hypotheses.append(item)


def transition_hypotheses(campaign_id: str, limit: int = 50) -> dict:
    observations = all_observations(campaign_id)
    graph = build_graph(campaign_id)

    hypotheses = []
    seen = set()

    by_id = {o["observation_id"]: o for o in observations}
    for change in graph.get("behavior_changes", []):
        if change.get("type") != "redirect_to_success":
            continue
        intermediate_ids = change.get("intermediate_observation_ids", [])
        if not intermediate_ids:
            continue
        checkpoints = []
        for obs_id in intermediate_ids:
            obs = by_id.get(obs_id)
            if not obs:
                continue
            checkpoints.append({
                "after_observation_id": obs_id,
                "after_action": obs["action"],
                "after_method": obs["method"],
                "after_path": obs["path"],
                "test_method": change["method"],
                "test_path": change["path"],
            })
        key = ("intermediate_access", change["actor_id"], change["method"], change["path"])
        _append_unique(hypotheses, seen, key, {
            "type": "intermediate_state_access",
            "confidence": "high",
            "title": f"Re-test {change['method']} {change['path']} after each intermediate workflow step",
            "actor_id": change["actor_id"],
            "method": change["method"],
            "path": change["path"],
            "evidence": [change["before"]["observation_id"], *intermediate_ids, change["after"]["observation_id"]],
            "checkpoints": checkpoints,
            "why": (
                "The same resource changed from a redirect response to a successful response after a sequence of intermediate "
                "requests. FlowState has no evidence showing exactly which intermediate transition is required before access becomes allowed."
            ),
            "expected_safe_behavior": (
                "Access remains denied until every security-relevant prerequisite in the workflow has completed."
            ),
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
            key = ("skip", actor_id, middle["observation_id"], right["method"], right["path"])
            _append_unique(hypotheses, seen, key, {
                "type": "skip_step",
                "confidence": "medium",
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
            "title": f"Re-test whether {obs['action']} is safely one-time or idempotent",
            "actor_id": obs["actor_id"],
            "method": obs["method"],
            "path": obs["path"],
            "evidence": [obs["observation_id"]],
            "why": "A state-changing request succeeded, but FlowState has no proof that repeating the same transition is rejected or safely idempotent.",
            "expected_safe_behavior": "The server rejects an invalid repeated transition or returns a harmless idempotent result.",
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
            "title": f"Validate forbidden transitions around {t['field']}",
            "actor_id": t["actor_id"],
            "path": t["path"],
            "evidence": [t["observation_id"]],
            "why": "A concrete state transition was observed. Adjacent, skipped, reversed, or repeated transitions remain unknown.",
            "manual_validation_required": True,
        })

    return {"campaign_id": campaign_id, "hypotheses": hypotheses[:max(1, min(limit, 200))]}


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
