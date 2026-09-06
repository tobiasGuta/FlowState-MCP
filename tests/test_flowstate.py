import base64
import json
from xml.sax.saxutils import escape

import pytest

from flowstate import store
from flowstate.analyzer import actor_permissions, build_graph, object_history
from flowstate.hypotheses import actor_swap_hypotheses, transition_hypotheses
from flowstate.importers import import_burp_xml, import_har
from flowstate.sanitize import sanitize_headers, summarize_body


@pytest.fixture
def temp_root(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOWSTATE_DATA_DIR", str(tmp_path / "data"))
    return tmp_path


def test_sensitive_headers_are_redacted():
    out = sanitize_headers({
        "Authorization": "Bearer super-secret",
        "Cookie": "session=abc",
        "Location": "/private?token=secret",
        "Content-Type": "application/json",
    })
    assert out["Authorization"] == "[REDACTED]"
    assert out["Cookie"] == "[REDACTED]"
    assert out["Location"] == "[REDACTED]"
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
                    "startedDateTime": "2026-09-06T14:00:00Z",
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
                    "startedDateTime": "2026-09-06T14:00:01Z",
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
    assert result["chronology_sorted"] is True
    assert result["timestamped"] == 1

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


def _raw_request(method: str, path: str, cookie: str, body: str = "", content_type: str | None = None) -> str:
    headers = [
        f"{method} {path} HTTP/2",
        "Host: example.com",
        f"Cookie: session={cookie}",
    ]
    if content_type:
        headers.append(f"Content-Type: {content_type}")
    return "\r\n".join(headers) + "\r\n\r\n" + body


def _raw_response(status: int, location: str | None = None, set_session: str | None = None, body: str = "") -> str:
    reason = "OK" if status == 200 else "Found"
    headers = [f"HTTP/2 {status} {reason}"]
    if location is not None:
        headers.append(f"Location: {location}")
    if set_session is not None:
        headers.append(f"Set-Cookie: session={set_session}; Secure; HttpOnly")
    if body:
        headers.append("Content-Type: text/html")
    return "\r\n".join(headers) + "\r\n\r\n" + body


def _burp_item(time_value: str, url: str, method: str, path: str, request_raw: str, status: int, response_raw: str) -> str:
    req_b64 = base64.b64encode(request_raw.encode()).decode()
    resp_b64 = base64.b64encode(response_raw.encode()).decode()
    return f"""
    <item>
      <time>{escape(time_value)}</time>
      <url>{escape(url)}</url>
      <host>example.com</host>
      <port>443</port>
      <protocol>https</protocol>
      <method>{method}</method>
      <path>{escape(path)}</path>
      <extension>null</extension>
      <request base64="true">{req_b64}</request>
      <status>{status}</status>
      <responselength>0</responselength>
      <mimetype></mimetype>
      <response base64="true">{resp_b64}</response>
      <comment></comment>
    </item>
    """


def test_burp_chronology_redirect_session_and_skip_step_reasoning(temp_root):
    campaign = store.create_campaign("State machine", "example.com")
    cid = campaign["campaign_id"]
    store.register_actor(cid, "user", "User", ["authenticated_user"])

    items = [
        _burp_item(
            "Sun Sep 06 10:03:35 EDT 2026",
            "https://example.com/login",
            "POST",
            "/login",
            _raw_request("POST", "/login", "SESSION0", "username=user&password=SECRET", "application/x-www-form-urlencoded"),
            302,
            _raw_response(302, "/role-selector", "SESSION1"),
        ),
        _burp_item(
            "Sun Sep 06 10:03:23 EDT 2026",
            "https://example.com/login",
            "GET",
            "/login",
            _raw_request("GET", "/login", "SESSION0"),
            200,
            _raw_response(200, body="<html>login</html>"),
        ),
        _burp_item(
            "Sun Sep 06 10:03:22 EDT 2026",
            "https://example.com/my-account",
            "GET",
            "/my-account",
            _raw_request("GET", "/my-account", "SESSION0"),
            302,
            _raw_response(302, "/login"),
        ),
        _burp_item(
            "Sun Sep 06 10:04:08 EDT 2026",
            "https://example.com/my-account?id=user",
            "GET",
            "/my-account?id=user",
            _raw_request("GET", "/my-account?id=user", "SESSION3"),
            200,
            _raw_response(200, body="<html>account</html>"),
        ),
        _burp_item(
            "Sun Sep 06 10:03:59 EDT 2026",
            "https://example.com/role-selector",
            "POST",
            "/role-selector",
            _raw_request("POST", "/role-selector", "SESSION2", "role=user&csrf=CSRFSECRET", "application/x-www-form-urlencoded"),
            302,
            _raw_response(302, "/", "SESSION3"),
        ),
        _burp_item(
            "Sun Sep 06 10:03:36 EDT 2026",
            "https://example.com/role-selector",
            "GET",
            "/role-selector",
            _raw_request("GET", "/role-selector", "SESSION1"),
            200,
            _raw_response(200, set_session="SESSION2", body="<html>role</html>"),
        ),
    ]
    xml = "<?xml version='1.0'?><items>" + "".join(items) + "</items>"
    xml_path = temp_root / "workflow.xml"
    xml_path.write_text(xml, encoding="utf-8")

    result = import_burp_xml(cid, "user", str(xml_path))
    assert result["accepted"] == 6
    assert result["chronology_sorted"] is True
    assert result["timestamped"] == 6

    observations = store.list_observations(cid, "user", 100)
    assert [(o["method"], o["path"], o["status"]) for o in observations] == [
        ("GET", "/my-account", 302),
        ("GET", "/login", 200),
        ("POST", "/login", 302),
        ("GET", "/role-selector", 200),
        ("POST", "/role-selector", 302),
        ("GET", "/my-account", 200),
    ]
    assert [o["sequence_index"] for o in observations] == [1, 2, 3, 4, 5, 6]

    login_post = observations[2]
    assert login_post["response"]["headers"]["Location"] == "[REDACTED]"
    assert login_post["response"]["redirect"] == {
        "path": "/role-selector",
        "query_parameter_names": [],
        "same_target": True,
    }
    assert login_post["session"]["session_changed"] is True
    assert login_post["session"]["request_session_fingerprint"]
    assert login_post["session"]["response_session_fingerprint"]

    serialized = json.dumps(observations)
    for secret in ["SESSION0", "SESSION1", "SESSION2", "SESSION3", "SECRET", "CSRFSECRET"]:
        assert secret not in serialized

    graph = build_graph(cid)
    assert graph["sequence_edge_count"] == 5
    assert any(t["type"] == "session_rotation" and t["path"] == "/login" for t in graph["transitions"])
    assert any(
        c["type"] == "redirect_to_success" and c["path"] == "/my-account"
        for c in graph["behavior_changes"]
    )

    hypotheses = transition_hypotheses(cid)["hypotheses"]
    assert any(
        h["type"] == "intermediate_state_access" and h["path"] == "/my-account"
        for h in hypotheses
    )
    assert any(
        h["type"] == "skip_step"
        and h["skipped_observation_id"] == "obs-5"
        and h["destination"]["path"] == "/my-account"
        for h in hypotheses
    )


def test_campaign_rejects_url_as_target_host(temp_root):
    with pytest.raises(store.FlowStateError):
        store.create_campaign("bad", "https://example.com")
