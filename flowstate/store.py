from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from .config import data_root

SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

class FlowStateError(ValueError):
    pass

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _safe_id(value: str, label: str) -> str:
    value = str(value)
    if not SAFE_ID.fullmatch(value):
        raise FlowStateError(f"Invalid {label}. Use only letters, numbers, dot, underscore, or dash.")
    return value

def _campaign_dir(campaign_id: str) -> Path:
    cid = _safe_id(campaign_id, "campaign_id")
    path = (data_root() / "campaigns" / cid).resolve()
    expected = (data_root() / "campaigns").resolve()
    if expected not in path.parents:
        raise FlowStateError("Campaign path escaped data root.")
    return path

def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    temp.replace(path)

def _read_json(path: Path, default=None):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))

def _append_jsonl(path: Path, item: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(item, sort_keys=True) + "\n")

def audit(campaign_id: str, event: str, details: dict | None = None) -> None:
    _append_jsonl(
        _campaign_dir(campaign_id) / "audit.jsonl",
        {"timestamp": now_iso(), "event": event, "details": details or {}},
    )

def create_campaign(name: str, target_host: str, notes: str | None = None) -> dict:
    if not name.strip():
        raise FlowStateError("name is required")
    host = target_host.strip().lower()
    if not host or "/" in host or "://" in host:
        raise FlowStateError("target_host must be a hostname, not a URL")

    cid = f"fs-{secrets.token_hex(6)}"
    cdir = _campaign_dir(cid)
    cdir.mkdir(parents=True, exist_ok=False)
    metadata = {
        "campaign_id": cid,
        "name": name.strip()[:200],
        "target_host": host[:253],
        "notes": (notes or "")[:2000],
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "schema_version": 1,
    }
    _write_json(cdir / "campaign.json", metadata)
    _write_json(cdir / "actors.json", [])
    _write_json(cdir / "observations.json", [])
    audit(cid, "campaign_created", {"target_host": host})
    return metadata

def get_campaign(campaign_id: str) -> dict:
    data = _read_json(_campaign_dir(campaign_id) / "campaign.json")
    if not data:
        raise FlowStateError("Campaign not found")
    return data

def list_campaigns(limit: int = 50) -> list[dict]:
    base = data_root() / "campaigns"
    if not base.exists():
        return []
    items = []
    for p in sorted(base.iterdir()):
        if not p.is_dir():
            continue
        data = _read_json(p / "campaign.json")
        if data:
            items.append(data)
    items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return items[: max(1, min(int(limit), 200))]

def register_actor(campaign_id: str, actor_id: str, name: str, roles: list[str] | None = None, notes: str | None = None) -> dict:
    get_campaign(campaign_id)
    aid = _safe_id(actor_id, "actor_id")
    actors_path = _campaign_dir(campaign_id) / "actors.json"
    actors = _read_json(actors_path, [])
    if any(a["actor_id"] == aid for a in actors):
        raise FlowStateError("actor_id already exists")
    actor = {
        "actor_id": aid,
        "name": name.strip()[:200],
        "roles": sorted(set((roles or [])[:50])),
        "notes": (notes or "")[:1000],
        "created_at": now_iso(),
    }
    actors.append(actor)
    _write_json(actors_path, actors)
    audit(campaign_id, "actor_registered", {"actor_id": aid, "roles": actor["roles"]})
    return actor

def list_actors(campaign_id: str) -> list[dict]:
    get_campaign(campaign_id)
    return _read_json(_campaign_dir(campaign_id) / "actors.json", [])

def actor_exists(campaign_id: str, actor_id: str) -> bool:
    return any(a["actor_id"] == actor_id for a in list_actors(campaign_id))

def save_observations(campaign_id: str, observations: list[dict], max_observations: int) -> dict:
    get_campaign(campaign_id)
    path = _campaign_dir(campaign_id) / "observations.json"
    existing = _read_json(path, [])
    room = max(0, max_observations - len(existing))
    accepted = observations[:room]
    existing.extend(accepted)
    _write_json(path, existing)
    audit(campaign_id, "observations_saved", {"accepted": len(accepted), "dropped": len(observations) - len(accepted)})
    return {
        "accepted": len(accepted),
        "dropped": len(observations) - len(accepted),
        "total": len(existing),
    }

def list_observations(campaign_id: str, actor_id: str | None = None, limit: int = 200) -> list[dict]:
    get_campaign(campaign_id)
    observations = _read_json(_campaign_dir(campaign_id) / "observations.json", [])
    if actor_id:
        observations = [o for o in observations if o.get("actor_id") == actor_id]
    limit = max(1, min(int(limit), 1000))
    return observations[-limit:]

def all_observations(campaign_id: str) -> list[dict]:
    get_campaign(campaign_id)
    return _read_json(_campaign_dir(campaign_id) / "observations.json", [])
