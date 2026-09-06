import base64
from xml.sax.saxutils import escape

import pytest

from flowstate import store
from flowstate.importers import import_burp_xml


@pytest.fixture
def temp_root(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOWSTATE_DATA_DIR", str(tmp_path / "data"))
    return tmp_path


def _raw_request(method: str, path: str, cookie: str, referer: str | None = None) -> str:
    headers = [
        f"{method} {path} HTTP/2",
        "Host: example.com",
        f"Cookie: session={cookie}",
    ]
    if referer:
        headers.append(f"Referer: {referer}")
    return "\r\n".join(headers) + "\r\n\r\n"


def _raw_response(status: int, location: str | None = None, set_session: str | None = None) -> str:
    reason = "OK" if status == 200 else "Found"
    headers = [f"HTTP/2 {status} {reason}"]
    if location is not None:
        headers.append(f"Location: {location}")
    if set_session is not None:
        headers.append(f"Set-Cookie: session={set_session}; Secure; HttpOnly")
    return "\r\n".join(headers) + "\r\n\r\n"


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


def test_same_second_burp_items_use_passive_ordering_evidence(temp_root):
    campaign = store.create_campaign("Same-second chronology", "example.com")
    cid = campaign["campaign_id"]
    store.register_actor(cid, "user", "User", ["authenticated_user"])

    # Deliberately use Burp XML order that is wrong inside each same-second pair.
    items = [
        _burp_item(
            "Sun Sep 06 10:55:27 EDT 2026",
            "https://example.com/",
            "GET",
            "/",
            _raw_request("GET", "/", "SESSION3", "https://example.com/role-selector"),
            200,
            _raw_response(200),
        ),
        _burp_item(
            "Sun Sep 06 10:54:51 EDT 2026",
            "https://example.com/login",
            "GET",
            "/login",
            _raw_request("GET", "/login", "SESSION0"),
            200,
            _raw_response(200),
        ),
        _burp_item(
            "Sun Sep 06 10:55:24 EDT 2026",
            "https://example.com/role-selector",
            "GET",
            "/role-selector",
            _raw_request("GET", "/role-selector", "SESSION1", "https://example.com/login"),
            200,
            _raw_response(200, set_session="SESSION2"),
        ),
        _burp_item(
            "Sun Sep 06 10:54:51 EDT 2026",
            "https://example.com/my-account",
            "GET",
            "/my-account",
            _raw_request("GET", "/my-account", "SESSION0"),
            302,
            _raw_response(302, "/login"),
        ),
        _burp_item(
            "Sun Sep 06 10:55:27 EDT 2026",
            "https://example.com/role-selector",
            "POST",
            "/role-selector",
            _raw_request("POST", "/role-selector", "SESSION2"),
            302,
            _raw_response(302, "/", "SESSION3"),
        ),
        _burp_item(
            "Sun Sep 06 10:55:24 EDT 2026",
            "https://example.com/login",
            "POST",
            "/login",
            _raw_request("POST", "/login", "SESSION0"),
            302,
            _raw_response(302, "/role-selector", "SESSION1"),
        ),
    ]

    xml_path = temp_root / "same-second.xml"
    xml_path.write_text("<?xml version='1.0'?><items>" + "".join(items) + "</items>", encoding="utf-8")

    result = import_burp_xml(cid, "user", str(xml_path))
    assert result["accepted"] == 6
    assert result["chronology_sorted"] is True
    assert result["chronology_basis_counts"]["redirect"] == 2
    assert result["chronology_basis_counts"]["session_continuity"] == 4

    observations = store.list_observations(cid, "user", 100)
    assert [(o["method"], o["path"]) for o in observations] == [
        ("GET", "/my-account"),
        ("GET", "/login"),
        ("POST", "/login"),
        ("GET", "/role-selector"),
        ("POST", "/role-selector"),
        ("GET", "/"),
    ]
    assert [o["sequence_index"] for o in observations] == [1, 2, 3, 4, 5, 6]
    assert [o["sequence_order_basis"] for o in observations] == [
        "redirect",
        "redirect",
        "session_continuity",
        "session_continuity",
        "session_continuity",
        "session_continuity",
    ]
    assert observations[3]["request"]["referer"] == {
        "path": "/login",
        "query_parameter_names": [],
        "same_target": True,
    }

    serialized = str(observations)
    for secret in ["SESSION0", "SESSION1", "SESSION2", "SESSION3"]:
        assert secret not in serialized


def test_referer_breaks_tie_when_session_and_redirect_do_not(temp_root):
    campaign = store.create_campaign("Referer chronology", "example.com")
    cid = campaign["campaign_id"]
    store.register_actor(cid, "user", "User", [])

    items = [
        _burp_item(
            "Sun Sep 06 11:00:00 EDT 2026",
            "https://example.com/step-two",
            "GET",
            "/step-two",
            _raw_request("GET", "/step-two", "SAME", "https://example.com/step-one"),
            200,
            _raw_response(200),
        ),
        _burp_item(
            "Sun Sep 06 11:00:00 EDT 2026",
            "https://example.com/step-one",
            "GET",
            "/step-one",
            _raw_request("GET", "/step-one", "SAME"),
            200,
            _raw_response(200),
        ),
    ]
    xml_path = temp_root / "referer.xml"
    xml_path.write_text("<?xml version='1.0'?><items>" + "".join(items) + "</items>", encoding="utf-8")

    result = import_burp_xml(cid, "user", str(xml_path))
    assert result["chronology_basis_counts"]["referer"] == 2
    observations = store.list_observations(cid, "user", 100)
    assert [o["path"] for o in observations] == ["/step-one", "/step-two"]
    assert all(o["sequence_order_basis"] == "referer" for o in observations)
