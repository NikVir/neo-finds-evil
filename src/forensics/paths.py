"""Extract filesystem path from Plaso fs:stat / MFT record."""

from __future__ import annotations

from typing import Any


def extract_file_path(raw: dict[str, Any]) -> str:
    """Prefer display_name, then filename; skip JSON pathspec blobs."""
    for key in ("display_name", "filename", "name"):
        val = raw.get(key)
        if not val or not isinstance(val, str):
            continue
        s = val.strip()
        if len(s) < 2:
            continue
        if key == "pathspec" and ("{" in s or "location" in s.lower()):
            continue
        return s.replace("/", "\\")
    pathspec = raw.get("pathspec")
    if isinstance(pathspec, str) and "\\" in pathspec and "{" not in pathspec:
        return pathspec.replace("/", "\\")
    return ""


def file_node_id(hostname: str, path: str) -> str:
    return f"{hostname}:{path}"
