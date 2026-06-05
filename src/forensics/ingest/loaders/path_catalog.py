"""Full fs:stat path catalog ingest (batched File nodes)."""

from __future__ import annotations

import json
from pathlib import Path

from forensics.cache import IngestCache, stream_ndjson
from forensics.plaso_export import iter_psort_jsonl
from forensics.case import CaseManifest
from forensics.discovery import discovery_from_case
from forensics.ingest.loaders.base import OptionalLoader
from forensics.normalize import normalize_record
from forensics.paths import extract_file_path, file_node_id
from forensics.registry import ArtifactCheck, ArtifactStatus, check_artifact

BATCH_SIZE = 2000
MAX_UNIQUE_PATHS = 100_000


class PathCatalogLoader(OptionalLoader):
    name = "path_catalog"
    _case: CaseManifest | None = None

    def set_case(self, case: CaseManifest) -> None:
        self._case = case

    def _fsstat_filter(self) -> str:
        base = 'data_type is "fs:stat"'
        if not self._case:
            return base
        disc = discovery_from_case(self._case)
        tokens = [t for t in disc.token_keywords if len(t) >= disc.min_keyword_len][:12]
        if not tokens:
            return base
        parts = [f'filename contains "{t}"' for t in tokens]
        return f"{base} and ({' or '.join(parts)})"

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
                reason="plaso store available for path catalog export",
            )
        return check_artifact(path, required=False)

    def load(self) -> int:
        path = self.path()
        if path.exists() and path.stat().st_size > 0:
            return self._ingest_jsonl(path)
        plaso = self.manifest.plaso_store
        if plaso and plaso.exists():
            return self._export_and_ingest(plaso, path)
        return 0

    def _ingest_jsonl(self, path: Path) -> int:
        spill = self.manifest.spill_dir or self.manifest.data_dir / ".ingest_cache"
        cache = IngestCache(spill, self.hostname, "path_catalog", batch_size=BATCH_SIZE)
        seen: set[str] = set()
        count = 0
        for raw in stream_ndjson(path, normalize_record):
            fpath = extract_file_path(raw)
            if not fpath or fpath in seen:
                continue
            seen.add(fpath)
            if len(seen) > MAX_UNIQUE_PATHS:
                break
            cache.add(
                {
                    "file_id": file_node_id(self.hostname, fpath),
                    "path": fpath,
                    "name": fpath.split("\\")[-1] if "\\" in fpath else fpath.split("/")[-1],
                    "hostname": self.hostname,
                    "source": "filestat",
                    "macb": str(raw.get("timestamp_desc") or ""),
                    "size": raw.get("file_size") or raw.get("size"),
                    "mtime": str(raw.get("datetime") or ""),
                }
            )
            count += 1
        cache.flush()
        for batch in cache.iter_batches():
            self._write_batch(batch)
        return count

    def _write_batch(self, batch: list) -> None:
        self.client.run_batched(
            """
            UNWIND $rows AS r
            MERGE (f:File {id: r.file_id})
            SET f.path = r.path, f.name = r.name, f.source = r.source,
                f.macb = r.macb, f.size = r.size, f.mtime = r.mtime
            MERGE (h:Host {hostname: r.hostname})
            MERGE (f)-[:ON_HOST]->(h)
            """,
            batch,
        )

    def _export_and_ingest(self, plaso: Path, out: Path) -> int:
        out.parent.mkdir(parents=True, exist_ok=True)
        seen: set[str] = set()
        count = 0
        filter_expr = self._fsstat_filter()
        with out.open("w") as fh:
            for line in iter_psort_jsonl(plaso, filter_expr, limit=MAX_UNIQUE_PATHS):
                try:
                    raw = normalize_record(json.loads(line))
                except json.JSONDecodeError:
                    continue
                fpath = extract_file_path(raw)
                if not fpath or fpath in seen:
                    continue
                seen.add(fpath)
                fh.write(line + "\n")
                count += 1
                if count >= MAX_UNIQUE_PATHS:
                    break
        if count == 0:
            return 0
        return self._ingest_jsonl(out)
