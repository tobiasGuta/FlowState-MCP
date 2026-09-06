from __future__ import annotations

import pytest

from flowstate import store
from flowstate.queue import build_hypothesis_queue
from flowstate.validation import annotate_hypotheses, record_hypothesis_validation


@pytest.fixture
def temp_root(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOWSTATE_DATA_DIR", str(tmp_path / "data"))
    return tmp_path


def _parent() -> dict:
    return {
        "type": "intermediate_state_access",
        "confidence": "high",
        "priority_score": 100,
        "title": "Re-test GET /vault at observed workflow state boundaries",
        "actor_id": "member",
        "method": "GET",
        "path": "/vault",
        "workflow_span": {
            "before_observation_id": "obs-before",
            "after_observation_id": "obs-after",
            "intermediate_observation_ids": ["obs-login", "obs-step-two", "obs-final"],
        },
        "evidence": ["obs-before", "obs-login", "obs-step-two", "obs-final", "obs-after"],
        "manual_validation_required": True,
    }


def _checkpoint(observation_id: str, after_path: str, priority: int) -> dict:
    return {
        "type": "workflow_checkpoint_access",
        "confidence": "high",
        "priority_score": priority,
        "title": f"Test GET /vault immediately after POST {after_path}",
        "actor_id": "member",
        "method": "GET",
        "path": "/vault",
        "checkpoint": {
            "after_observation_id": observation_id,
            "after_action": "create_or_action",
            "after_method": "POST",
            "after_path": after_path,
            "state_boundary_reasons": ["successful_state_change"],
            "test_method": "GET",
            "test_path": "/vault",
        },
        "remaining_prerequisite_observation_ids": ["obs-final"],
        "evidence": ["obs-before", observation_id, "obs-final", "obs-after"],
        "manual_validation_required": True,
    }


def _replay(priority: int = 30) -> dict:
    return {
        "type": "replay_transition",
        "confidence": "medium",
        "priority_score": priority,
        "title": "Re-test whether state change is safely one-time or idempotent",
        "actor_id": "member",
        "method": "POST",
        "path": "/finalize",
        "evidence": ["obs-final"],
        "manual_validation_required": True,
    }


def test_supported_child_is_removed_and_parent_does_not_compete_with_concrete_children(temp_root):
    campaign = store.create_campaign("Queue", "example.com")
    cid = campaign["campaign_id"]
    first = _checkpoint("obs-login", "/signin", 95)
    second = _checkpoint("obs-step-two", "/step-two", 90)
    hypotheses = [_parent(), first, second, _replay()]

    annotated = annotate_hypotheses(cid, hypotheses)
    first_annotated = next(item for item in annotated if item["title"] == first["title"])
    record_hypothesis_validation(
        campaign_id=cid,
        hypothesis_id_value=first_annotated["hypothesis_id"],
        outcome="supported",
        test_method="GET",
        test_path="/vault",
        observed_status=200,
        known_hypothesis_ids={item["hypothesis_id"] for item in annotated},
    )

    queue = build_hypothesis_queue(cid, hypotheses, limit=20)
    titles = [item["title"] for item in queue["queue"]]

    assert first["title"] not in titles
    assert _parent()["title"] not in titles
    assert queue["queue"][0]["title"] == second["title"]
    assert queue["queue"][0]["queue_priority_score"] == 90
    assert queue["excluded_resolved_count"] == 1
    assert queue["suppressed_planning_count"] == 1
    assert queue["validation_status_counts"]["supported"] == 1

    regenerated = annotate_hypotheses(cid, hypotheses)
    parent = next(item for item in regenerated if item["type"] == "intermediate_state_access")
    supported = next(item for item in regenerated if item["title"] == first["title"])
    assert parent["validation_status"] == "untested"
    assert supported["validation_status"] == "supported"


def test_inconclusive_stays_actionable_with_retry_penalty(temp_root):
    campaign = store.create_campaign("Retry queue", "example.com")
    cid = campaign["campaign_id"]
    inconclusive = _checkpoint("obs-login", "/signin", 95)
    untested = _checkpoint("obs-step-two", "/step-two", 90)
    hypotheses = [inconclusive, untested]

    annotated = annotate_hypotheses(cid, hypotheses)
    target = next(item for item in annotated if item["title"] == inconclusive["title"])
    record_hypothesis_validation(
        campaign_id=cid,
        hypothesis_id_value=target["hypothesis_id"],
        outcome="inconclusive",
        test_method="GET",
        test_path="/vault",
        observed_status=503,
        known_hypothesis_ids={item["hypothesis_id"] for item in annotated},
    )

    queue = build_hypothesis_queue(cid, hypotheses, limit=20)
    assert [item["title"] for item in queue["queue"]] == [untested["title"], inconclusive["title"]]
    retry = queue["queue"][1]
    assert retry["validation_status"] == "inconclusive"
    assert retry["base_priority_score"] == 95
    assert retry["queue_priority_score"] == 80
    assert retry["queue_status"] == "retry_inconclusive"

    without_retries = build_hypothesis_queue(cid, hypotheses, limit=20, include_inconclusive=False)
    assert [item["title"] for item in without_retries["queue"]] == [untested["title"]]
    assert without_retries["excluded_inconclusive_count"] == 1


def test_falsified_hypothesis_remains_in_history_but_is_not_next_action(temp_root):
    campaign = store.create_campaign("Resolved queue", "example.com")
    cid = campaign["campaign_id"]
    falsified = _checkpoint("obs-login", "/signin", 95)
    replay = _replay(30)
    hypotheses = [falsified, replay]

    annotated = annotate_hypotheses(cid, hypotheses)
    target = next(item for item in annotated if item["title"] == falsified["title"])
    record_hypothesis_validation(
        campaign_id=cid,
        hypothesis_id_value=target["hypothesis_id"],
        outcome="falsified",
        test_method="GET",
        test_path="/vault",
        observed_status=302,
        observed_redirect_path="/signin",
        known_hypothesis_ids={item["hypothesis_id"] for item in annotated},
    )

    queue = build_hypothesis_queue(cid, hypotheses, limit=20)
    assert [item["title"] for item in queue["queue"]] == [replay["title"]]
    assert queue["validation_status_counts"]["falsified"] == 1
    assert queue["excluded_resolved_count"] == 1

    regenerated = annotate_hypotheses(cid, hypotheses)
    resolved = next(item for item in regenerated if item["title"] == falsified["title"])
    assert resolved["validation_status"] == "falsified"
    assert resolved["validation_count"] == 1
