import json
from pathlib import Path

import pytest

from flowstate import store
from flowstate.analyzer import actor_permissions, build_graph, object_history
from flowstate.hypotheses import actor_swap_hypotheses, transition_hypotheses
from flowstate.importers import import_har
from flowstate.sanitize import sanitize_headers, summarize_body

@pytest.fixture
def temp_root(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOWSTATE_DATA_DIR", str(tmp_path / "data"))
    return tmp_path

def test_sensitive_headers_are_redacted():
    out = sanitize_headers({
        "Authorization": "Bearer super-secret",
        "Cookie": "session=abc",
        "Content-Type": "application/json",
    })
    assert out["Authorization"] == "[REDACTED]"
    assert out["Cookie"] == "[REDACTED]"
    assert out["Content-Type"] == "application/json"

def test_body_extracts_ids_and_state_but_not_tokens():
    body = json.dumps({
        "workspace_id": "ws_1",
        "status": "pending",
        "access_token": "do-not-store",
    })
    out = summarize_body(body, "application/json", 10000)
    assert any(i["value"] == "ws_1" for i in out["identifiers"])
    assert any(i["value"] == "pending" for i in out["state_fields"])
    assert "access_token" in out["field_names"]
    assert all(i["field"] != "access_token" for i in out["identifiers"])

def test_har_import_graph_and_hypotheses(temp_root):
    campaign = store.create_campaign("Demo", "example.com")
    cid = campaign["campaign_id"]
    store.register_actor(cid, "owner", "Owner", ["owner"])
    store.register_actor(cid, "member", "Member", ["member"])

    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://example.com/api/invitations/inv_1/accept",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer SECRET"},
                            {"name": "Content-Type", "value": "application/json"},
                        ],
                        "postData": {"text": json.dumps({"invitation_id": "inv_1", "status": "pending"})},
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"text": json.dumps({"invitation_id": "inv_1", "status": "accepted"})},
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://evil.example.net/nope",
                        "headers": [],
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {"text": "{}"},
                    },
                },
            ]
        }
    }

    har_path = temp_root / "sample.har"
    har_path.write_text(json.dumps(har), encoding="utf-8")

    result = import_har(cid, "owner", str(har_path))
    assert result["accepted"] == 1
    assert result["skipped_out_of_target"] == 1

    graph = build_graph(cid)
    assert graph["node_count"] >= 2
    assert graph["transition_count"] >= 1

    perms = actor_permissions(cid)
    assert "owner" in perms["actors"]

    hist = object_history(cid, "inv_1")
    assert hist["count"] == 1

    th = transition_hypotheses(cid)
    assert any(h["type"] == "replay_transition" for h in th["hypotheses"])

    ah = actor_swap_hypotheses(cid)
    assert any(h["candidate_actor"] == "member" for h in ah["hypotheses"])

def test_campaign_rejects_url_as_target_host(temp_root):
    with pytest.raises(store.FlowStateError):
        store.create_campaign("bad", "https://example.com")
