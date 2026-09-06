from __future__ import annotations

import os
from pathlib import Path

DEFAULT_MAX_IMPORT_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_OBSERVATIONS = 5000
DEFAULT_MAX_BODY_BYTES = 256 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024

def _bounded_int(name: str, default: int, low: int, high: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if low <= value <= high else default

def data_root() -> Path:
    root = Path(os.getenv("FLOWSTATE_DATA_DIR", "output")).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root

def limits() -> dict:
    return {
        "max_import_bytes": _bounded_int(
            "FLOWSTATE_MAX_IMPORT_BYTES", DEFAULT_MAX_IMPORT_BYTES, 1024, 100 * 1024 * 1024
        ),
        "max_observations": _bounded_int(
            "FLOWSTATE_MAX_OBSERVATIONS", DEFAULT_MAX_OBSERVATIONS, 1, 100_000
        ),
        "max_body_bytes": _bounded_int(
            "FLOWSTATE_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES, 1024, 2 * 1024 * 1024
        ),
        "max_response_bytes": _bounded_int(
            "FLOWSTATE_MAX_RESPONSE_BYTES", DEFAULT_MAX_RESPONSE_BYTES, 4096, 4 * 1024 * 1024
        ),
    }
