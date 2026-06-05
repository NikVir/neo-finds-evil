"""Normalize Windows paths for cross-artifact correlation."""

from __future__ import annotations

import re

from forensics.paths import file_node_id

_DEVICE_VOLUME_RE = re.compile(
    r"^\\Device\\HarddiskVolume(\d+)\\",
    re.IGNORECASE,
)
_DEFAULT_VOLUME_MAP: dict[str, str] = {
    "1": "C:\\",
    "2": "D:\\",
    "3": "E:\\",
}


def normalize_windows_path(
    path: str,
    *,
    volume_map: dict[str, str] | None = None,
) -> str:
    """Normalize path for File node IDs and correlate joins."""
    if not path or not isinstance(path, str):
        return ""
    s = path.strip().strip('"').replace("/", "\\")
    if not s:
        return ""

    vol_map = volume_map or _DEFAULT_VOLUME_MAP
    m = _DEVICE_VOLUME_RE.match(s)
    if m:
        vol = m.group(1)
        rest = s[m.end() :]
        prefix = vol_map.get(vol, "C:\\")
        if not prefix.endswith("\\"):
            prefix += "\\"
        s = prefix + rest

    if s.startswith("\\") and not s.lower().startswith("\\device\\"):
        s = "C:" + s

    while "\\\\" in s:
        s = s.replace("\\\\", "\\")

    return s


def normalized_file_id(
    hostname: str,
    path: str,
    *,
    volume_map: dict[str, str] | None = None,
) -> tuple[str, str]:
    """Return (normalized_path, file_node_id). Empty path -> ('', '')."""
    norm = normalize_windows_path(path, volume_map=volume_map)
    if not norm:
        return "", ""
    return norm, file_node_id(hostname, norm)
