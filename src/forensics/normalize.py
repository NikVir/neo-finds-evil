"""Normalize Volatility / Plaso field names to snake_case."""

from __future__ import annotations

import re
from typing import Any

_KEY_MAP = {
    "PID": "pid",
    "PPID": "ppid",
    "File output": "file_output",
    "Offset(V)": "offset_v",
    "ImageFileName": "image_file_name",
    "CreateTime": "create_time",
    "ExitTime": "exit_time",
    "ForeignAddr": "foreign_addr",
    "ForeignPort": "foreign_port",
    "LocalAddr": "local_addr",
    "LocalPort": "local_port",
    "event_identifier": "event_id",
    "display_name": "display_name",
    "timestamp_desc": "timestamp_desc",
    "datetime": "datetime",
    "date_time": "datetime",
    "xml_string": "xml_string",
    "filename": "filename",
    "inode": "inode",
}


def _to_snake(key: str) -> str:
    if key in _KEY_MAP:
        return _KEY_MAP[key]
    if key.startswith("_"):
        return key
    s1 = re.sub(r"([A-Z])", r"_\1", key.replace(" ", "_"))
    return s1.lower().strip("_")


def normalize_record(raw: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in raw.items():
        nk = _to_snake(k) if isinstance(k, str) else k
        out[nk] = v
    return out


def process_id(hostname: str, pid: int | str, create_time: str) -> str:
    ct = (create_time or "unknown").replace(":", "-")
    return f"{hostname}:{pid}:{ct}"
