from __future__ import annotations

import pytest

from flowstate import store
from flowstate.queue import build_hypothesis_queue
from flowstate.validation import annotate_hypotheses, record_hypothesis_validation


@pytest.fixture
def temp_root(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOWSTATE_DATA_DIR", str(tmp_path / "data"))
    return tmp_path


def _checkpoint(
    observation_id: str,
    *,
    actor_id: str = "member",
    destination_path: str = "/vault",
    remaining: list[str] | None = None,
    priority: int = 90,
) -> dict:
    return {
        "type": "workflow_checkpoint_access",
        "confidence": "high",
        "priority_score": priority,
        "title": f"Test GET {destination_path} after checkpoint {observation_id}",
        "actor_id": actor_id,
        "method": "GET",
        "path": destination_path,
        "checkpoint": {
            "after_observation_id": observation_id,
            "after_action": "create_or_action",
            "after_method": "POST",
            "after_path": f"/step/{observation_id}",
            "state_boundary_reasons": ["successful_state_change"],
            "test_method": "GET",
            "test_path": destination_path,
        },
        "remaining_prerequisite_observation_ids": list(remaining or []),
        "evidence": ["obs-before", observation_id, *(remaining or []), "obs-after"],
        "manual_validation_required": True,
    }


def _skip(
    skipped_observation_id: str,
    *,
    actor_id: str = "member",
    destination_path: str = "/vault",
    priority: int = 50,
) -> dict:
    return {
        "type": "skip_step",
        "confidence": "medium",
        "priority_score": priority,
        "title": f"Test whether {skipped_observation_id} can be skipped before GET {destination_path}",
        "actor_id": actor_id,
        "precondition_observation_id": "obs-before-skip",
        "skipped_observation_id": skipped_observation_id,
        "destination_observation_id": "obs-destination",
        "destination": {"method": "GET", "path": destination_path},
        "evidence": ["obs-before-skip", skipped_observation_id, "obs-destination"],
        "manual_validation_required": True,
    }


def _replay() -> dict:
    return {
        "type": "replay_transition",
        "confidence": "medium",
        "priority_score": 30,
        "title": "Re-test whether finalization is safely one-time or idempotent",
        "actor_id": "member",
        "method": "POST",
        "path": "/finalize",
        "evidence": ["obs-final"],
        "manual_validation_required": True,
    }


def _record_supported(campaign_id: str, hypotheses: list[dict], target_title: str) -> str:
    annotated = annotate_hypotheses(campaign_id, hypotheses)
    target = next(item for item in annotated if item["title"] == target_title)
    record_hypothesis_validation(
        campaign_id=campaign_id,
        hypothesis_id_value=target["hypothesis_id"],
        outcome="supported",
        test_method="GET",
        test_path=target.get("path") or "/vault",
        observed_status=200,
        known_hypothesis_ids={item["hypothesis_id"] for item in annotated},
    )
    return target["hypothesis_id"]


def test_supported_earlier_checkpoint_subsumes_later_checkpoint_and_later_skip(temp_root):
    campaign = store.create_campaign("Dominance", "example.com")
    cid = campaign["campaign_id"]

    earlier = _checkpoint("obs-a", remaining=["obs-b", "obs-c"], priority=95)
    later = _checkpoint("obs-b", remaining=["obs-c"], priority=90)
    skip = _skip("obs-c")
    replay = _replay()
    hypotheses = [earlier, later, skip, replay]

    supported_id = _record_supported(cid, hypotheses, earlier["title"])
    queue = build_hypothesis_queue(cid, hypotheses, limit=20)

    assert [item["title"] for item in queue["queue"]] == [replay["title"]]
    assert queue["subsumed_count"] == 2
    assert queue["excluded_resolved_count"] == 1
    assert queue["total_actionable_count"] == 1

    by_title = {item["title"]: item for item in queue["subsumed"]}
    assert by_title[later["title"]]["queue_status"] == "subsumed"
    assert by_title[later["title"]]["subsumed_by"] == supported_id
    assert by_title[later["title"]]["subsumption_relation"] == "later_checkpoint"
    assert by_title[later["title"]]["validation_status"] == "untested"

    assert by_title[skip["title"]]["queue_status"] == "subsumed"
    assert by_title[skip["title"]]["subsumed_by"] == supported_id
    assert by_title[skip["title"]]["subsumption_relation"] == "later_prerequisite"
    assert by_title[skip["title"]]["validation_status"] == "untested"


def test_supported_later_checkpoint_does_not_subsume_earlier_checkpoint(temp_root):
    campaign = store.create_campaign("Directionality", "example.com")
    cid = campaign["campaign_id"]

    earlier = _checkpoint("obs-a", remaining=["obs-b"], priority=95)
    later = _checkpoint("obs-b", remaining=[], priority=90)
    hypotheses = [earlier, later]

    _record_supported(cid, hypotheses, later["title"])
    queue = build_hypothesis_queue(cid, hypotheses, limit=20)

    assert [item["title"] for item in queue["queue"]] == [earlier["title"]]
    assert queue["subsumed_count"] == 0
    assert queue["excluded_resolved_count"] == 1


def test_subsumption_requires_same_actor_and_destination(temp_root):
    campaign = store.create_campaign("Scope", "example.com")
    cid = campaign["campaign_id"]

    source = _checkpoint("obs-a", remaining=["obs-b"], priority=95)
    other_destination = _checkpoint(
        "obs-b",
        destination_path="/billing",
        remaining=[],
        priority=90,
    )
    other_actor = _checkpoint(
        "obs-b",
        actor_id="outsider",
        destination_path="/vault",
        remaining=[],
        priority=85,
    )
    hypotheses = [source, other_destination, other_actor]

    _record_supported(cid, hypotheses, source["title"])
    queue = build_hypothesis_queue(cid, hypotheses, limit=20)

    assert {item["title"] for item in queue["queue"]} == {
        other_destination["title"],
        other_actor["title"],
    }
    assert queue["subsumed_count"] == 0

    regenerated = annotate_hypotheses(cid, hypotheses)
    unresolved = [item for item in regenerated if item["title"] != source["title"]]
    assert all(item["validation_status"] == "untested" for item in unresolved)
