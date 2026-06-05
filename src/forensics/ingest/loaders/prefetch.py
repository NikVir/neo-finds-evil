"""Prefetch execution evidence -> Host-[:EXECUTED]->File."""

from __future__ import annotations

from typing import Any

from forensics.ingest.loaders.base import OptionalLoader
from forensics.ingest.loaders.execution_common import (
    artifact_check_with_plaso,
    extract_execution_path,
    ingest_executed_files,
)
from forensics.path_normalize import normalized_file_id
from forensics.plaso_filters import PREFETCH_FILTER
from forensics.registry import ArtifactCheck
from forensics.timestamps import normalize_timestamp


def _prefetch_row(raw: dict[str, Any], hostname: str, source: str) -> dict[str, Any] | None:
    path = extract_execution_path(raw)
    norm, file_id = normalized_file_id(hostname, path)
    if not file_id:
        return None
    name = norm.split("\\")[-1] if "\\" in norm else norm.split("/")[-1]
    run_count = (
        raw.get("run_count") or raw.get("run_count_total") or raw.get("number_of_executions")
    )
    try:
        run_val = int(run_count) if run_count is not None else None
    except (TypeError, ValueError):
        run_val = None
    return {
        "hostname": hostname,
        "file_id": file_id,
        "path": norm,
        "name": name,
        "file_source": "prefetch",
        "source": source,
        "timestamp": normalize_timestamp(
            raw.get("last_run")
            or raw.get("last_run_time")
            or raw.get("timestamp")
            or raw.get("datetime")
        ),
        "order": None,
        "run_count": run_val,
    }


class PrefetchLoader(OptionalLoader):
    name = "prefetch"

    def check(self) -> ArtifactCheck:
        return artifact_check_with_plaso(self, PREFETCH_FILTER)

    def load(self) -> int:
        return ingest_executed_files(
            self,
            source="prefetch",
            path=self.path(),
            plaso_filter=PREFETCH_FILTER,
            row_builder=_prefetch_row,
        )
