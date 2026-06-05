"""Shimcache / AppCompat execution evidence -> Host-[:EXECUTED]->File."""

from __future__ import annotations

from typing import Any

from forensics.ingest.loaders.base import OptionalLoader
from forensics.ingest.loaders.execution_common import (
    artifact_check_with_plaso,
    extract_execution_path,
    ingest_executed_files,
)
from forensics.path_normalize import normalized_file_id
from forensics.plaso_filters import SHIMCACHE_FILTER
from forensics.registry import ArtifactCheck
from forensics.timestamps import normalize_timestamp


def _shim_row(raw: dict[str, Any], hostname: str, source: str) -> dict[str, Any] | None:
    path = extract_execution_path(raw)
    norm, file_id = normalized_file_id(hostname, path)
    if not file_id:
        return None
    name = norm.split("\\")[-1] if "\\" in norm else norm.split("/")[-1]
    order = raw.get("order") or raw.get("index") or raw.get("entry_index")
    try:
        order_val = int(order) if order is not None else None
    except (TypeError, ValueError):
        order_val = None
    return {
        "hostname": hostname,
        "file_id": file_id,
        "path": norm,
        "name": name,
        "file_source": "shimcache",
        "source": source,
        "timestamp": normalize_timestamp(
            raw.get("timestamp")
            or raw.get("last_modified")
            or raw.get("datetime")
            or raw.get("last_modified_time")
        ),
        "order": order_val,
        "run_count": None,
    }


class ShimcacheLoader(OptionalLoader):
    name = "shimcache"

    def check(self) -> ArtifactCheck:
        return artifact_check_with_plaso(self, SHIMCACHE_FILTER)

    def load(self) -> int:
        return ingest_executed_files(
            self,
            source="shimcache",
            path=self.path(),
            plaso_filter=SHIMCACHE_FILTER,
            row_builder=_shim_row,
        )
