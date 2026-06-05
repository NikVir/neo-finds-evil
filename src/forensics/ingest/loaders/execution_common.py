"""Shared helpers for shimcache/prefetch execution ingest."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from forensics.cache import IngestCache, stream_ndjson
from forensics.ingest.loaders.base import OptionalLoader
from forensics.normalize import normalize_record
from forensics.plaso_export import iter_psort_jsonl
from forensics.registry import ArtifactCheck, ArtifactStatus, check_artifact


def extract_execution_path(raw: dict[str, Any]) -> str:
    for key in (
        "path",
        "executable_path",
        "executable",
        "cache_entry_path",
        "display_name",
        "filename",
        "full_path",
    ):
        val = raw.get(key)
        if val and isinstance(val, str) and len(val.strip()) > 2:
            return val.strip()
    return ""


def artifact_check_with_plaso(loader: OptionalLoader, plaso_filter: str) -> ArtifactCheck:
    path = loader.path()
    if path.exists() and path.stat().st_size > 0:
        return ArtifactCheck(name=loader.name, path=path, status=ArtifactStatus.READY)
    plaso = loader.manifest.plaso_store
    if plaso and plaso.exists():
        return ArtifactCheck(
            name=loader.name,
            path=path,
            status=ArtifactStatus.READY,
            reason=f"plaso store available ({plaso_filter})",
        )
    return check_artifact(path, required=False)


def ingest_executed_files(
    loader: OptionalLoader,
    *,
    source: str,
    path: Path,
    plaso_filter: str | None,
    row_builder,
) -> int:
    """Stream JSONL or Plaso export; MERGE File + Host-[:EXECUTED]."""
    if path.exists() and path.stat().st_size > 0:
        return _ingest_stream(loader, source, path, row_builder)
    plaso = loader.manifest.plaso_store
    if plaso and plaso.exists() and plaso_filter:
        return _export_and_ingest(loader, source, plaso, path, plaso_filter, row_builder)
    return 0


def _ingest_stream(loader, source: str, path: Path, row_builder) -> int:
    spill = loader.manifest.spill_dir or loader.manifest.data_dir / ".ingest_cache"
    cache = IngestCache(spill, loader.hostname, loader.name)
    count = 0
    seen: set[str] = set()
    for raw in stream_ndjson(path, normalize_record):
        row = row_builder(raw, loader.hostname, source)
        if not row or row["file_id"] in seen:
            continue
        seen.add(row["file_id"])
        cache.add(row)
        count += 1
    cache.flush()
    _flush_executed(loader, cache)
    return count


def _export_and_ingest(loader, source, plaso, out_path, plaso_filter, row_builder) -> int:
    lines = list(iter_psort_jsonl(plaso, plaso_filter, output_path=out_path))
    if not lines:
        return 0
    spill = loader.manifest.spill_dir or loader.manifest.data_dir / ".ingest_cache"
    cache = IngestCache(spill, loader.hostname, loader.name)
    count = 0
    seen: set[str] = set()
    for line in lines:
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        raw = normalize_record(raw)
        row = row_builder(raw, loader.hostname, source)
        if not row or row["file_id"] in seen:
            continue
        seen.add(row["file_id"])
        cache.add(row)
        count += 1
    cache.flush()
    _flush_executed(loader, cache)
    return count


def _flush_executed(loader, cache: IngestCache) -> None:
    for batch in cache.iter_batches():
        loader.client.run_batched(
            """
            UNWIND $rows AS r
            MERGE (h:Host {hostname: r.hostname})
            MERGE (f:File {id: r.file_id})
            ON CREATE SET f.path = r.path, f.name = r.name, f.source = r.file_source
            SET f.path = coalesce(f.path, r.path), f.name = coalesce(f.name, r.name)
            MERGE (h)-[e:EXECUTED {source: r.source}]->(f)
            SET e.timestamp = r.timestamp, e.order = r.order, e.runCount = r.run_count,
                e.confidence = coalesce(e.confidence, 'direct')
            """,
            batch,
        )
