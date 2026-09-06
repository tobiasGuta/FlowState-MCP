from __future__ import annotations

import pytest

from flowstate import store
from flowstate.analyzer import build_graph
from flowstate.hypotheses import transition_hypotheses


@pytest.fixture
def temp_root(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOWSTATE_DATA_DIR", str(tmp_path / "data"))
    return tmp_path


def _empty_body() -> dict:
    return {
        "present": False,
        "format": "none",
        "field_names": [],
        "identifiers": [],
        "state_fields": [],
    }


def _obs(
    observation_id: str,
    sequence_index: int,
    method: str,
    path: str,
    status: int,
    *,
    action: str = "read",
    redirect: str | None = None,
    session_changed: bool = False,
) -> dict:
    redirect_value = None
    if redirect is not None:
        redirect_value = {
            "path": redirect,
            "query_parameter_names": [],
            "same_target": True,
        }

    before = f"before-{observation_id}" if session_changed else None
    after = f"after-{observation_id}" if session_changed else None
    return {
        "observation_schema_version": 3,
        "observation_id": observation_id,
        "timestamp": f"2026-09-06T15:00:{sequence_index:02d}+00:00",
        "imported_at": "2026-09-06T15:01:00+00:00",
        "sequence_index": sequence_index,
        "sequence_order_basis": "timestamp",
        "sequence_order_evidence": [],
        "actor_id": "user",
        "method": method,
        "url": f"https://example.com{path}",
        "path": path,
        "query_parameter_names": [],
        "status": status,
        "action": action,
        "request": {
            "header_names": [],
            "headers": {},
            "body": _empty_body(),
            "referer": None,
        },
        "response": {
            "header_names": [],
            "headers": {},
            "body": _empty_body(),
            "redirect": redirect_value,
        },
        "session": {
            "request_cookie_fingerprints": {},
            "response_cookie_fingerprints": {},
            "request_session_fingerprint": before,
            "response_session_fingerprint": after,
            "session_changed": session_changed,
        },
        "source": "test",
        "source_ref": observation_id,
    }


def test_generic_workflow_span_prioritizes_protected_destination_without_path_rules(temp_root):
    campaign = store.create_campaign("Generic workflow", "example.com")
    cid = campaign["campaign_id"]
    store.register_actor(cid, "user", "User", ["member"])

    observations = [
        _obs("obs-a", 1, "GET", "/vault", 302, redirect="/signin"),
        _obs("obs-b", 2, "GET", "/signin", 200),
        _obs("obs-c", 3, "POST", "/signin", 302, action="login", redirect="/wizard", session_changed=True),
        _obs("obs-d", 4, "GET", "/wizard", 200, session_changed=True),
        _obs("obs-e", 5, "POST", "/wizard", 302, action="create_or_action", redirect="/welcome", session_changed=True),
        _obs("obs-f", 6, "GET", "/welcome", 200),
        _obs("obs-g", 7, "GET", "/vault", 200),
    ]
    result = store.save_observations(cid, observations, 100)
    assert result["accepted"] == 7

    graph = build_graph(cid)
    assert graph["behavior_change_count"] == 1
    assert graph["security_relevant_destination_count"] == 1
    assert graph["security_relevant_destinations"][0]["path"] == "/vault"

    navigation = {item["observation_id"]: item for item in graph["navigation_observations"]}
    assert navigation["obs-b"]["pure_navigation"] is True
    assert navigation["obs-d"]["pure_navigation"] is False
    assert navigation["obs-d"]["state_boundary_reasons"] == ["session_rotation"]
    assert navigation["obs-f"]["pure_navigation"] is True

    hypotheses = transition_hypotheses(cid, 100)["hypotheses"]
    assert hypotheses[0]["type"] == "intermediate_state_access"
    assert hypotheses[0]["path"] == "/vault"
    assert hypotheses[0]["priority_score"] == 100
    assert [item["after_observation_id"] for item in hypotheses[0]["checkpoints"]] == [
        "obs-c",
        "obs-d",
        "obs-e",
    ]

    checkpoint_hypotheses = [item for item in hypotheses if item["type"] == "workflow_checkpoint_access"]
    assert [item["checkpoint"]["after_observation_id"] for item in checkpoint_hypotheses] == [
        "obs-c",
        "obs-d",
    ]
    assert all(item["path"] == "/vault" for item in checkpoint_hypotheses)
    assert all(item["confidence"] == "high" for item in checkpoint_hypotheses)

    # Redirect-follow pages are navigation edges, so they should not become low-value local skip destinations.
    assert not any(
        item["type"] == "skip_step" and item.get("destination", {}).get("path") in {"/wizard", "/welcome"}
        for item in hypotheses
    )


def test_production_workflow_rules_are_target_agnostic():
    # The regression fixture deliberately uses unrelated route names. The production rule should derive behavior
    # from status changes, redirects, session boundaries, and HTTP semantics rather than special-casing lab paths.
    from flowstate import workflow

    source = open(workflow.__file__, "r", encoding="utf-8").read()
    assert "/my-account" not in source
    assert "/role-selector" not in source
    assert "web-security-academy" not in source
