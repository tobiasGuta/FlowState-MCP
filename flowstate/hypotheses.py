from __future__ import annotations

from collections import defaultdict

from .analyzer import build_graph
from .store import all_observations, list_actors

STATEFUL_ACTIONS = {
    "accept", "approve", "verify", "invite", "promote", "demote", "remove", "delete",
    "revoke", "enable", "disable", "activate", "deactivate", "complete", "submit",
    "cancel", "archive", "restore", "create_or_action", "update",
}

def transition_hypotheses(campaign_id: str, limit: int = 50) -> dict:
    observations = all_observations(campaign_id)
    graph = build_graph(campaign_id)

    hypotheses = []
    seen = set()

    # Replay candidates: state-changing actions observed successfully at least once.
    for obs in observations:
        if obs["action"] not in STATEFUL_ACTIONS:
            continue
        if obs["status"] is None or obs["status"] >= 400:
            continue
        key = ("replay", obs["method"], obs["path"], obs["actor_id"])
        if key in seen:
            continue
        seen.add(key)
        hypotheses.append({
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

    # State field transitions can suggest reversal / skip checks.
    for t in graph["transitions"]:
        key = ("state", t["field"], t["before"], t["after"], t["path"])
        if key in seen:
            continue
        seen.add(key)
        hypotheses.append({
            "type": "state_transition",
            "confidence": "medium",
            "title": f"Validate forbidden transitions around {t['field']}: {t['before']} → {t['after']}",
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
