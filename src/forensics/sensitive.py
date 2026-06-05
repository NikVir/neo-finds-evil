"""Match file paths against case sensitive path patterns."""

from __future__ import annotations

import fnmatch
import re


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Convert Windows-style glob (* segments) to regex."""
    p = pattern.replace("\\", "/")
    parts = [re.escape(seg) for seg in p.split("*")]
    return re.compile(".*".join(parts), re.IGNORECASE)


def path_matches_sensitive(
    path: str,
    patterns: list[str],
    extensions: list[str] | None = None,
) -> bool:
    if not path:
        return False
    norm = path.replace("\\", "/")
    for pat in patterns:
        rx = glob_to_regex(pat)
        if rx.search(norm):
            return True
        fn_pat = pat.replace("\\", "/")
        if fnmatch.fnmatch(norm.lower(), fn_pat.lower()):
            return True
    if extensions:
        low = norm.lower()
        for ext in extensions:
            e = ext if ext.startswith(".") else f".{ext}"
            if low.endswith(e.lower()):
                return True
    return False
