"""Probe Plaso store for field names on a data type (sample lines)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from forensics.plaso_export import iter_psort_jsonl


def probe_plaso(
    plaso_path: Path,
    data_type: str = "fs:stat",
    limit: int = 5,
) -> dict[str, Any]:
    """Stream psort lines and return sample keys + records."""
    if not plaso_path.exists():
        return {"error": f"plaso store not found: {plaso_path}", "samples": []}

    filter_expr = f'data_type is "{data_type}"'
    samples: list[dict[str, Any]] = []
    all_keys: set[str] = set()
    for line in iter_psort_jsonl(plaso_path, filter_expr, limit=limit):
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        all_keys.update(raw.keys())
        samples.append(raw)
    return {
        "data_type": data_type,
        "filter": filter_expr,
        "keys": sorted(all_keys),
        "samples": samples,
    }
