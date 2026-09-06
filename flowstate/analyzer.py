from __future__ import annotations

import re
from collections import defaultdict

from .store import all_observations, list_actors
from .workflow import navigation_evidence

GENERIC_SEGMENTS = {
    "api", "v1", "v2", "v3", "users", "user", "accounts", "account",
    "organizations", "organization", "orgs", "teams", "team", "projects", "project",
    "members", "member", "invitations", "invites", "invite", "workspaces", "workspace",
}


def _path_entities(path: str) -> list[dict]:
    segments = [s for s in path.split("/") if s]
    entities = []
    for i, seg in enumerate(segments):
        lower = seg.lower()
        if lower in GENERIC_SEGMENTS:
            continue
        if re.fullmatch(r"[A-Za-z0-9._:-]{2,128}", seg):
            prev = segments[i - 1].lower() if i > 0 else "resource"
            if prev in {"v1", "v2", "v3", "api"}:
                prev = "resource"
            entities.append({"type": prev.rstrip("s") or "resource", "value": seg, "source": "path"})
    return entities


def _body_entities(summary: dict, source: str) -> list[dict]:
    result = []
    for item in summary.get("identifiers", []):
        result.append({
            "type": item.get("field", "identifier").lower(),
            "value": item.get("value"),
            "source": source,
            "path": item.get("path"),
        })
    return result


def _states(summary: dict, source: str) -> list[dict]:
    return [
        {
            "field": i.get("field"),
            "value": i.get("value"),
            "source": source,
            "path": i.get("path"),
        }
        for i in summary.get("state_fields", [])
    ]


def _sequence_edges(observations: list[dict]) -> list[dict]:
    by_actor: dict[str, list[dict]] = defaultdict(list)
    for obs in observations:
        by_actor[obs["actor_id"]].append(obs)

    edges = []
    for actor_id, actor_obs in by_actor.items():
        for left, right in zip(actor_obs, actor_obs[1:]):
            edges.append({
                "actor_id": actor_id,
                "from_observation_id": left["observation_id"],
                "to_observation_id": right["observation_id"],
                "from": {"method": left["method"], "path": left["path"], "status": left["status"]},
                "to": {"method": right["method"], "path": right["path"], "status": right["status"]},
            })
    return edges


def _behavior_changes(observations: list[dict]) -> list[dict]:
    by_actor_endpoint: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for obs in observations:
        by_actor_endpoint[(obs["actor_id"], obs["method"], obs["path"])].append(obs)

    changes = []
    for (actor_id, method, path), endpoint_obs in by_actor_endpoint.items():
        for before_index, before in enumerate(endpoint_obs):
            before_status = before.get("status")
            if before_status is None:
                continue
            for after in endpoint_obs[before_index + 1:]:
                after_status = after.get("status")
                if after_status is None or after_status == before_status:
                    continue
                if 300 <= before_status < 400 and 200 <= after_status < 300:
                    all_actor = [o for o in observations if o["actor_id"] == actor_id]
                    pos_before = all_actor.index(before)
                    pos_after = all_actor.index(after)
                    intermediate = all_actor[pos_before + 1:pos_after]
                    changes.append({
                        "type": "redirect_to_success",
                        "actor_id": actor_id,
                        "method": method,
                        "path": path,
                        "before": {
                            "observation_id": before["observation_id"],
                            "status": before_status,
                            "redirect": before.get("response", {}).get("redirect"),
                        },
                        "after": {
                            "observation_id": after["observation_id"],
                            "status": after_status,
                        },
                        "intermediate_observation_ids": [o["observation_id"] for o in intermediate],
                    })
                    break
    return changes


def _security_relevant_destinations(behavior_changes: list[dict]) -> list[dict]:
    destinations = []
    for change in behavior_changes:
        if change.get("type") != "redirect_to_success":
            continue
        destinations.append({
            "type": "access_gate_change",
            "actor_id": change.get("actor_id"),
            "method": change.get("method"),
            "path": change.get("path"),
            "before_observation_id": (change.get("before") or {}).get("observation_id"),
            "after_observation_id": (change.get("after") or {}).get("observation_id"),
            "before_status": (change.get("before") or {}).get("status"),
            "after_status": (change.get("after") or {}).get("status"),
            "reason": (
                "The same actor and endpoint changed from a redirect response to a successful response "
                "across an observed workflow span."
            ),
        })
    return destinations


def build_graph(campaign_id: str) -> dict:
    observations = all_observations(campaign_id)
    actors = {a["actor_id"]: a for a in list_actors(campaign_id)}

    nodes = {}
    edges = []
    transitions = []

    for obs in observations:
        actor_id = obs["actor_id"]
        nodes[f"actor:{actor_id}"] = {
            "id": f"actor:{actor_id}",
            "kind": "actor",
            "label": actors.get(actor_id, {}).get("name", actor_id),
            "roles": actors.get(actor_id, {}).get("roles", []),
        }

        entities = _path_entities(obs["path"])
        entities += _body_entities(obs["request"]["body"], "request_body")
        entities += _body_entities(obs["response"]["body"], "response_body")

        dedup = {}
        for e in entities:
            key = (e["type"], str(e["value"]))
            dedup[key] = e
        entities = list(dedup.values())

        for ent in entities[:50]:
            eid = f"entity:{ent['type']}:{ent['value']}"
            nodes[eid] = {
                "id": eid,
                "kind": "entity",
                "entity_type": ent["type"],
                "value": ent["value"],
            }
            edges.append({
                "from": f"actor:{actor_id}",
                "to": eid,
                "type": obs["action"],
                "observation_id": obs["observation_id"],
                "method": obs["method"],
                "path": obs["path"],
                "status": obs["status"],
            })

        request_states = _states(obs["request"]["body"], "request")
        response_states = _states(obs["response"]["body"], "response")
        for rs in request_states:
            matching = [x for x in response_states if x["field"].lower() == rs["field"].lower()]
            for after in matching:
                if rs["value"] != after["value"]:
                    transitions.append({
                        "type": "body_state",
                        "field": rs["field"],
                        "before": rs["value"],
                        "after": after["value"],
                        "actor_id": actor_id,
                        "action": obs["action"],
                        "path": obs["path"],
                        "observation_id": obs["observation_id"],
                    })

        session = obs.get("session") or {}
        before_session = session.get("request_session_fingerprint")
        after_session = session.get("response_session_fingerprint")
        if before_session and after_session and before_session != after_session:
            transitions.append({
                "type": "session_rotation",
                "field": "session_fingerprint",
                "before": before_session,
                "after": after_session,
                "actor_id": actor_id,
                "action": obs["action"],
                "path": obs["path"],
                "observation_id": obs["observation_id"],
            })

    sequence_edges = _sequence_edges(observations)
    behavior_changes = _behavior_changes(observations)
    navigation_observations = navigation_evidence(observations)
    security_relevant_destinations = _security_relevant_destinations(behavior_changes)
    return {
        "campaign_id": campaign_id,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "transition_count": len(transitions),
        "sequence_edge_count": len(sequence_edges),
        "behavior_change_count": len(behavior_changes),
        "navigation_observation_count": len(navigation_observations),
        "pure_navigation_count": sum(1 for item in navigation_observations if item.get("pure_navigation")),
        "security_relevant_destination_count": len(security_relevant_destinations),
        "nodes": list(nodes.values()),
        "edges": edges,
        "transitions": transitions,
        "sequence_edges": sequence_edges,
        "behavior_changes": behavior_changes,
        "navigation_observations": navigation_observations,
        "security_relevant_destinations": security_relevant_destinations,
    }


def actor_permissions(campaign_id: str) -> dict:
    observations = all_observations(campaign_id)
    matrix = defaultdict(lambda: defaultdict(lambda: {"count": 0, "statuses": set(), "paths": set()}))

    for obs in observations:
        key = f"{obs['method']} {obs['action']}"
        cell = matrix[obs["actor_id"]][key]
        cell["count"] += 1
        if obs["status"] is not None:
            cell["statuses"].add(obs["status"])
        cell["paths"].add(obs["path"])

    serial = {}
    for actor, actions in matrix.items():
        serial[actor] = {}
        for action, cell in actions.items():
            serial[actor][action] = {
                "count": cell["count"],
                "statuses": sorted(cell["statuses"]),
                "paths": sorted(cell["paths"])[:100],
            }

    return {"campaign_id": campaign_id, "actors": serial}


def object_history(campaign_id: str, entity_value: str) -> dict:
    observations = all_observations(campaign_id)
    matches = []
    needle = str(entity_value)

    for obs in observations:
        found = needle in obs["path"]
        if not found:
            for side in ("request", "response"):
                for item in obs[side]["body"].get("identifiers", []):
                    if str(item.get("value")) == needle:
                        found = True
                        break
                if found:
                    break
        if found:
            matches.append({
                "observation_id": obs["observation_id"],
                "timestamp": obs["timestamp"],
                "sequence_index": obs.get("sequence_index"),
                "actor_id": obs["actor_id"],
                "action": obs["action"],
                "method": obs["method"],
                "path": obs["path"],
                "status": obs["status"],
                "request_state_fields": obs["request"]["body"].get("state_fields", []),
                "response_state_fields": obs["response"]["body"].get("state_fields", []),
                "source": obs["source"],
                "source_ref": obs["source_ref"],
            })

    return {"entity_value": needle, "observations": matches, "count": len(matches)}
