from __future__ import annotations

import re
from collections import defaultdict

from .store import all_observations, list_actors

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
                        "field": rs["field"],
                        "before": rs["value"],
                        "after": after["value"],
                        "actor_id": actor_id,
                        "action": obs["action"],
                        "path": obs["path"],
                        "observation_id": obs["observation_id"],
                    })

    return {
        "campaign_id": campaign_id,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "transition_count": len(transitions),
        "nodes": list(nodes.values()),
        "edges": edges,
        "transitions": transitions,
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
