"""Normalize forensic timestamps to ISO-8601 UTC strings."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


def normalize_timestamp(value: Any) -> str:
    """Best-effort ISO-8601 from Plaso/Volatility/EVTX string or numeric forms."""
    if value is None or value == "":
        return ""
    if isinstance(value, (int, float)):
        return _from_numeric(value)
    s = str(value).strip()
    if not s:
        return ""
    if s.isdigit():
        return _from_numeric(int(s))
    if re.match(r"^\d{10,}$", s):
        return _from_numeric(int(s))
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ):
        try:
            dt = datetime.strptime(s.replace("Z", ""), fmt.replace("Z", ""))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    m = re.search(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", s)
    if m:
        return f"{m.group(1)}T{m.group(2)}Z"
    return s


def _from_numeric(n: int | float) -> str:
    """Windows FILETIME (100-ns since 1601) or Unix epoch seconds."""
    if n > 1_000_000_000_000_000_000:
        unix = (n / 10_000_000) - 11_644_473_600
    elif n > 1_000_000_000_000:
        unix = n / 1000.0
    elif n > 1_000_000_000:
        unix = float(n)
    else:
        return ""
    try:
        dt = datetime.fromtimestamp(unix, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OSError, OverflowError, ValueError):
        return ""
