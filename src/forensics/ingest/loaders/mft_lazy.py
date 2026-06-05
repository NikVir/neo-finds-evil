"""Lazy MFT/filestat ingest for IOC paths only (case discovery seeds)."""

from __future__ import annotations

import json
from pathlib import Path

from forensics.cache import IngestCache, stream_ndjson
from forensics.plaso_export import iter_psort_jsonl
from forensics.case import CaseManifest
from forensics.discovery import collect_discovery_seeds
from forensics.ingest.loaders.base import OptionalLoader
from forensics.normalize import normalize_record
from forensics.paths import extract_file_path, file_node_id
from forensics.registry import ArtifactCheck, ArtifactStatus, check_artifact


def collect_ioc_paths(
    client,
    hostname: str,
    case: CaseManifest | None = None,
) -> set[str]:
    """Gather paths from graph and case discovery config for lazy MFT correlation."""
    if case:
        return collect_discovery_seeds(case, client, hostname)
    paths: set[str] = set()
    for rec in client.query(
        """
        MATCH (f:File) WHERE f.id STARTS WITH $prefix
        RETURN f.path AS path LIMIT 5000
        """,
        {"prefix": f"{hostname}:"},
    ):
        if rec.get("path"):
            paths.add(str(rec["path"]).replace("/", "\\"))
    for hint in ("iCloud", "OneDrive", "Google", "SRL", "Documents", "Design"):
        paths.add(hint)
    return paths


def _path_matches(filename: str, ioc_paths: set[str]) -> bool:
    norm = filename.replace("/", "\\").lower()
    for p in ioc_paths:
        pl = p.lower()
        if len(pl) < 3:
            continue
        if pl in norm or norm.endswith(pl.split("\\")[-1]):
            return True
    return False


class MftLazyLoader(OptionalLoader):
    name = "mft"
    _case: CaseManifest | None = None

    def set_case(self, case: CaseManifest) -> None:
        self._case = case

    def check(self) -> ArtifactCheck:
        path = self.path()
        if path.exists() and path.stat().st_size > 0:
            return ArtifactCheck(name=self.name, path=path, status=ArtifactStatus.READY)
        plaso = self.manifest.plaso_store
        if plaso and plaso.exists():
            return ArtifactCheck(
                name=self.name,
                path=path,
                status=ArtifactStatus.READY,
                reason="plaso store available for lazy export",
            )
        return check_artifact(path, required=False)

    def load(self) -> int:
        ioc_paths = collect_ioc_paths(self.client, self.hostname, self._case)
        if not ioc_paths:
            return 0

        path = self.path()
        if path.exists() and path.stat().st_size > 0:
            return self._ingest_jsonl(path, ioc_paths)

        plaso = self.manifest.plaso_store
        if plaso and plaso.exists():
            return self._export_and_ingest(plaso, path, ioc_paths)

        return 0

    def _ingest_jsonl(self, path: Path, ioc_paths: set[str]) -> int:
        spill = self.manifest.spill_dir or self.manifest.data_dir / ".ingest_cache"
        cache = IngestCache(spill, self.hostname, "mft")
        count = 0
        for raw in stream_ndjson(path, normalize_record):
            filename = extract_file_path(raw) or raw.get("filename") or ""
            if not _path_matches(filename, ioc_paths):
                continue
            file_id = file_node_id(self.hostname, filename)
            cache.add(
                {
                    "file_id": file_id,
                    "path": filename,
                    "hostname": self.hostname,
                    "timestamp": str(raw.get("datetime") or ""),
                    "macb": raw.get("timestamp_desc") or "",
                }
            )
            count += 1
        cache.flush()
        for batch in cache.iter_batches():
            self.client.run_batched(
                """
                UNWIND $rows AS r
                MERGE (f:File {id: r.file_id})
                SET f.path = r.path, f.type = 'mft', f.source = coalesce(f.source, 'mft')
                MERGE (h:Host {hostname: r.hostname})
                MERGE (f)-[:ON_HOST]->(h)
                """,
                batch,
            )
        return count

    def _export_and_ingest(self, plaso: Path, out: Path, ioc_paths: set[str]) -> int:
        out.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        with out.open("w") as fh:
            for line in iter_psort_jsonl(plaso, 'data_type is "fs:stat"', limit=50000):
                try:
                    raw = normalize_record(json.loads(line))
                except json.JSONDecodeError:
                    continue
                filename = extract_file_path(raw) or raw.get("filename") or ""
                if not _path_matches(filename, ioc_paths):
                    continue
                fh.write(line + "\n")
                count += 1
        if count == 0:
            return 0
        return self._ingest_jsonl(out, ioc_paths)
