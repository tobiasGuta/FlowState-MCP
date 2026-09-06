import json

import pytest

from flowstate import store
from flowstate.validation import annotate_hypotheses, record_hypothesis_validation


@pytest.fixture
def temp_root(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOWSTATE_DATA_DIR", str(tmp_path / "data"))
    return tmp_path


def _checkpoint_hypothesis() -> dict:
    return {
        "type": "workflow_checkpoint_access",
        "confidence": "high",
        "priority_score": 95,
        "title": "Test GET /vault immediately after POST /signin",
        "actor_id": "member",
        "method": "GET",
        "path": "/vault",
        "checkpoint": {
            "after_observation_id": "obs-login",
            "after_action": "login",
            "after_method": "POST",
            "after_path": "/signin",
            "state_boundary_reasons": ["session_rotation", "successful_state_change"],
            "test_method": "GET",
            "test_path": "/vault",
        },
        "remaining_prerequisite_observation_ids": ["obs-setup"],
        "evidence": ["obs-before", "obs-login", "obs-setup", "obs-after"],
        "manual_validation_required": True,
    }


def test_validation_persists_and_is_attached_to_regenerated_hypothesis(temp_root):
    campaign = store.create_campaign("Lifecycle", "example.com")
    cid = campaign["campaign_id"]

    first = annotate_hypotheses(cid, [_checkpoint_hypothesis()])[0]
    assert first["hypothesis_id"].startswith("hyp-")
    assert first["validation_status"] == "untested"
    assert first["validation_count"] == 0
    assert first["latest_validation"] is None

    record = record_hypothesis_validation(
        campaign_id=cid,
        hypothesis_id_value=first["hypothesis_id"],
        outcome="supported",
        test_method="GET",
        test_path="/vault?id=do-not-store",
        observed_status=200,
        observed_redirect_path=None,
        notes="access succeeded; session=DO-NOT-STORE password=DO-NOT-STORE",
        known_hypothesis_ids={first["hypothesis_id"]},
    )
    assert record["outcome"] == "supported"
    assert record["test"] == {"method": "GET", "path": "/vault"}
    assert record["observed"] == {"status": 200, "redirect_path": None}

    serialized = json.dumps(record)
    assert "DO-NOT-STORE" not in serialized
    assert "[REDACTED]" in serialized

    regenerated_input = _checkpoint_hypothesis()
    regenerated_input["priority_score"] = 80
    regenerated_input["confidence"] = "medium"
    regenerated_input["title"] = "Updated wording that must not change semantic identity"
    regenerated = annotate_hypotheses(cid, [regenerated_input])[0]

    assert regenerated["hypothesis_id"] == first["hypothesis_id"]
    assert regenerated["validation_status"] == "supported"
    assert regenerated["validation_count"] == 1
    assert regenerated["latest_validation"]["observed"]["status"] == 200


def test_validation_rejects_unknown_or_invalid_hypothesis(temp_root):
    campaign = store.create_campaign("Validation guard", "example.com")
    cid = campaign["campaign_id"]
    hypothesis = annotate_hypotheses(cid, [_checkpoint_hypothesis()])[0]

    with pytest.raises(store.FlowStateError):
        record_hypothesis_validation(
            campaign_id=cid,
            hypothesis_id_value="hyp-0000000000000000",
            outcome="supported",
            test_method="GET",
            test_path="/vault",
            known_hypothesis_ids={hypothesis["hypothesis_id"]},
        )

    with pytest.raises(store.FlowStateError):
        record_hypothesis_validation(
            campaign_id=cid,
            hypothesis_id_value=hypothesis["hypothesis_id"],
            outcome="confirmed-vulnerability",
            test_method="GET",
            test_path="/vault",
            known_hypothesis_ids={hypothesis["hypothesis_id"]},
        )


def test_validation_paths_are_structured_and_query_values_are_not_persisted(temp_root):
    campaign = store.create_campaign("Structured evidence", "example.com")
    cid = campaign["campaign_id"]
    hypothesis = annotate_hypotheses(cid, [_checkpoint_hypothesis()])[0]

    record = record_hypothesis_validation(
        campaign_id=cid,
        hypothesis_id_value=hypothesis["hypothesis_id"],
        outcome="falsified",
        test_method="GET",
        test_path="/vault?object=secret-value",
        observed_status=302,
        observed_redirect_path="/signin?next=/vault&token=secret-value",
        known_hypothesis_ids={hypothesis["hypothesis_id"]},
    )

    assert record["test"]["path"] == "/vault"
    assert record["observed"]["redirect_path"] == "/signin"
    assert "secret-value" not in json.dumps(record)
