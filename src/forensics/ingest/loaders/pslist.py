"""Ingest Volatility pslist -> Host, Process, SPAWNED."""

from __future__ import annotations

from forensics.cache import IngestCache, stream_ndjson
from forensics.ingest.loaders.base import BaseLoader
from forensics.normalize import normalize_record, process_id


class PslistLoader(BaseLoader):
    name = "pslist"
    required = True

    def load(self) -> int:
        path = self.path()
        spill = self.manifest.spill_dir or self.manifest.data_dir / ".ingest_cache"
        cache = IngestCache(spill, self.hostname, "pslist")
        count = 0

        self.client.run(
            "MERGE (h:Host {hostname: $hostname}) SET h.id = $hostname, h.caseId = $case_id",
            {"hostname": self.hostname, "case_id": self.manifest.case_id},
        )

        for raw in stream_ndjson(path, normalize_record):
            pid = raw.get("pid")
            if pid is None:
                continue
            create_time = str(raw.get("create_time") or "unknown")
            pid_s = process_id(self.hostname, pid, create_time)
            cache.add(
                {
                    "id": pid_s,
                    "pid": int(pid),
                    "ppid": int(raw["ppid"]) if raw.get("ppid") is not None else None,
                    "name": raw.get("image_file_name") or raw.get("name") or "",
                    "create_time": create_time,
                    "exit_time": raw.get("exit_time"),
                    "source": "vol_pslist",
                    "hostname": self.hostname,
                }
            )
            count += 1

        cache.flush()
        for batch in cache.iter_batches():
            self.client.run_batched(
                """
                UNWIND $rows AS r
                MERGE (h:Host {hostname: r.hostname})
                SET h.id = r.hostname
                MERGE (p:Process {id: r.id})
                SET p.pid = r.pid, p.ppid = r.ppid, p.name = r.name,
                    p.createTime = r.create_time, p.exitTime = r.exit_time,
                    p.source = r.source
                MERGE (p)-[:RAN_ON]->(h)
                """,
                batch,
            )

        # SPAWNED from ppid (tentative) — second pass over source file
        spawn_cache = IngestCache(spill, self.hostname, "pslist_spawn")
        for raw in stream_ndjson(path, normalize_record):
            pid = raw.get("pid")
            ppid = raw.get("ppid")
            if pid is None or not ppid or int(ppid) <= 0:
                continue
            create_time = str(raw.get("create_time") or "unknown")
            spawn_cache.add(
                {
                    "id": process_id(self.hostname, pid, create_time),
                    "ppid": int(ppid),
                    "hostname": self.hostname,
                }
            )
        spawn_cache.flush()
        for batch in spawn_cache.iter_batches():
            self.client.run_batched(
                """
                UNWIND $rows AS r
                MATCH (child:Process {id: r.id})
                MATCH (parent:Process)
                WHERE parent.pid = r.ppid AND parent.id STARTS WITH r.hostname + ':'
                MERGE (parent)-[s:SPAWNED]->(child)
                SET s.confidence = 'tentative', s.source = 'vol_pslist'
                """,
                batch,
            )

        return count
