"""Ingest Volatility dlllist -> LOADED_MODULE."""

from __future__ import annotations

from forensics.cache import IngestCache, stream_ndjson
from forensics.ingest.loaders.base import OptionalLoader
from forensics.normalize import normalize_record


class DlllistLoader(OptionalLoader):
    name = "dlllist"

    def load(self) -> int:
        path = self.path()
        spill = self.manifest.spill_dir or self.manifest.data_dir / ".ingest_cache"
        cache = IngestCache(spill, self.hostname, "dlllist")
        count = 0

        for raw in stream_ndjson(path, normalize_record):
            pid = raw.get("pid")
            path_str = raw.get("path") or raw.get("name") or ""
            if pid is None or not path_str:
                continue
            file_id = f"{self.hostname}:{path_str}"
            cache.add(
                {
                    "pid": int(pid),
                    "hostname": self.hostname,
                    "file_id": file_id,
                    "path": path_str,
                    "name": raw.get("name") or "",
                    "load_time": raw.get("load_time"),
                    "base": raw.get("base"),
                    "size": raw.get("size"),
                }
            )
            count += 1

        cache.flush()
        for batch in cache.iter_batches():
            self.client.run_batched(
                """
                UNWIND $rows AS r
                MATCH (p:Process)
                WHERE p.pid = r.pid AND p.id STARTS WITH r.hostname + ':'
                WITH r, p ORDER BY p.createTime DESC
                WITH r, head(collect(p)) AS proc
                MERGE (f:File {id: r.file_id})
                SET f.path = r.path, f.name = r.name, f.type = 'dll'
                MERGE (proc)-[m:LOADED_MODULE]->(f)
                SET m.loadTime = r.load_time, m.base = r.base, m.size = r.size
                """,
                batch,
            )

        return count
