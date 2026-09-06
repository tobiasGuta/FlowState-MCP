from __future__ import annotations

import hashlib
import json
import re
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urljoin, urlsplit

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "location",
    "referer",
}

SENSITIVE_KEY_RE = re.compile(
    r"(token|secret|password|passwd|pwd|api[_-]?key|authorization|cookie|session|jwt|"
    r"refresh[_-]?token|access[_-]?token|id[_-]?token|code_verifier|client_secret|"
    r"otp|nonce|verification[_-]?code|reset[_-]?code|auth(?:orization)?[_-]?code)",
    re.I,
)

ID_KEY_RE = re.compile(
    r"(^id$|_id$|Id$|ID$|uuid$|guid$|slug$|key$|code$|invite$|invitation$|"
    r"workspace$|organization$|org$|team$|project$|member$|user$|account$)",
    re.I,
)

STATE_KEY_RE = re.compile(
    r"(status|state|phase|stage|role|enabled|active|verified|approved|accepted|revoked|"
    r"deleted|completed|visibility|permission|plan|tier)",
    re.I,
)

OPAQUE_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{24,}$")


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]


def safe_scalar(value) -> str | None:
    if value is None:
        return None
    sval = str(value)
    if not sval:
        return None
    if "@" in sval and " " not in sval:
        return None
    if len(sval) > 512:
        return f"<opaque:{fingerprint(sval)}>"
    if len(sval) >= 24 and OPAQUE_RE.fullmatch(sval):
        return f"<opaque:{fingerprint(sval)}>"
    return sval[:256]


def sanitize_path(path: str) -> str:
    segments = path.split("/")
    out = []
    for segment in segments:
        if len(segment) >= 24 and OPAQUE_RE.fullmatch(segment):
            out.append(f"opaque-{fingerprint(segment)}")
        else:
            out.append(segment[:256])
    return "/".join(out)


def _header_values(headers, wanted_name: str) -> list[str]:
    wanted = wanted_name.lower()
    values: list[str] = []
    if isinstance(headers, dict):
        for name, value in headers.items():
            if str(name).lower() == wanted:
                values.append(str(value))
    elif isinstance(headers, list):
        for item in headers:
            if not isinstance(item, dict):
                continue
            if str(item.get("name", "")).lower() == wanted:
                values.append(str(item.get("value", "")))
    return values


def sanitize_headers(headers) -> dict:
    result = {}
    if isinstance(headers, dict):
        items = headers.items()
    elif isinstance(headers, list):
        items = []
        for h in headers:
            if isinstance(h, dict):
                items.append((str(h.get("name", "")), str(h.get("value", ""))))
    else:
        items = []
    for name, value in items:
        lname = str(name).lower()
        if lname in SENSITIVE_HEADER_NAMES or SENSITIVE_KEY_RE.search(lname):
            result[str(name)] = "[REDACTED]"
        else:
            result[str(name)] = str(value)[:1024]
    return result


def sanitize_query(url: str) -> tuple[str, list[str]]:
    p = urlsplit(url)
    names = []
    for key, _value in parse_qsl(p.query, keep_blank_values=True):
        names.append(key)
    clean = f"{p.scheme}://{p.netloc}{p.path}" if p.scheme and p.netloc else p.path
    return clean, sorted(set(names))


def sanitize_redirect(headers, target_host: str) -> dict | None:
    values = _header_values(headers, "location")
    if not values:
        return None
    raw = values[-1].strip()
    if not raw:
        return None

    absolute = urljoin(f"https://{target_host}/", raw)
    parsed = urlsplit(absolute)
    host = (parsed.hostname or "").lower()
    query_names = sorted({k for k, _v in parse_qsl(parsed.query, keep_blank_values=True)})
    result = {
        "path": sanitize_path(parsed.path or "/"),
        "query_parameter_names": query_names,
        "same_target": host == target_host or host.endswith("." + target_host),
    }
    if not result["same_target"]:
        result["host"] = host[:253]
    return result


def cookie_fingerprints(headers) -> dict[str, str]:
    """Return only cookie-name -> short hash mappings; never cookie values."""
    result: dict[str, str] = {}
    for raw in _header_values(headers, "cookie"):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for name, morsel in cookie.items():
            if morsel.value:
                result[str(name)[:128]] = fingerprint(morsel.value)
    return result


def set_cookie_fingerprints(headers) -> dict[str, str]:
    """Return only Set-Cookie name -> short hash mappings; never cookie values."""
    result: dict[str, str] = {}
    for raw in _header_values(headers, "set-cookie"):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for name, morsel in cookie.items():
            if morsel.value:
                result[str(name)[:128]] = fingerprint(morsel.value)
    return result


def _walk_json(value, prefix="$", depth=0, max_depth=6, out=None):
    if out is None:
        out = {
            "field_names": set(),
            "identifiers": [],
            "state_fields": [],
        }
    if depth > max_depth:
        return out

    if isinstance(value, dict):
        for key, child in value.items():
            skey = str(key)
            out["field_names"].add(skey)

            if SENSITIVE_KEY_RE.search(skey):
                continue

            if isinstance(child, (str, int, float, bool)) or child is None:
                if ID_KEY_RE.search(skey):
                    sval = safe_scalar(child)
                    if sval:
                        out["identifiers"].append(
                            {"field": skey, "value": sval, "path": f"{prefix}.{skey}"}
                        )
                if STATE_KEY_RE.search(skey):
                    sval = safe_scalar(child)
                    if sval:
                        out["state_fields"].append(
                            {"field": skey, "value": sval, "path": f"{prefix}.{skey}"}
                        )

            _walk_json(child, f"{prefix}.{skey}", depth + 1, max_depth, out)

    elif isinstance(value, list):
        for i, child in enumerate(value[:100]):
            _walk_json(child, f"{prefix}[{i}]", depth + 1, max_depth, out)

    return out


def summarize_body(body: str | bytes | None, content_type: str | None, max_bytes: int) -> dict:
    if body is None:
        return {"present": False, "format": "none", "field_names": [], "identifiers": [], "state_fields": []}

    if isinstance(body, bytes):
        raw = body[:max_bytes]
        text = raw.decode("utf-8", errors="replace")
    else:
        text = str(body)[:max_bytes]

    result = {
        "present": bool(text),
        "format": "text",
        "field_names": [],
        "identifiers": [],
        "state_fields": [],
    }

    ctype = (content_type or "").lower()
    stripped = text.lstrip()

    if "json" in ctype or stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed = json.loads(text)
        except Exception:
            return result
        walked = _walk_json(parsed)
        result.update({
            "format": "json",
            "field_names": sorted(walked["field_names"]),
            "identifiers": walked["identifiers"][:200],
            "state_fields": walked["state_fields"][:200],
        })
        return result

    if "application/x-www-form-urlencoded" in ctype:
        names = []
        identifiers = []
        states = []
        for key, value in parse_qsl(text, keep_blank_values=True):
            names.append(key)
            if SENSITIVE_KEY_RE.search(key):
                continue
            safe = safe_scalar(value)
            if ID_KEY_RE.search(key) and safe:
                identifiers.append({"field": key, "value": safe, "path": f"$.{key}"})
            if STATE_KEY_RE.search(key) and safe:
                states.append({"field": key, "value": safe, "path": f"$.{key}"})
        result.update({
            "format": "form",
            "field_names": sorted(set(names)),
            "identifiers": identifiers[:200],
            "state_fields": states[:200],
        })
    return result
