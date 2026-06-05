"""Ingest Volatility netscan -> CONNECTED_TO."""

from __future__ import annotations

from forensics.cache import IngestCache, stream_ndjson
from forensics.ingest.loaders.base import OptionalLoader
from forensics.normalize import normalize_record


def _skip_addr(addr: str | None) -> bool:
    if not addr or addr in ("0.0.0.0", "0.0.0.0:0", "*", "-"):
        return True
    return addr.startswith("127.") or addr == "::1"


class NetscanLoader(OptionalLoader):
    name = "netscan"

    def load(self) -> int:
        path = self.path()
        spill = self.manifest.spill_dir or self.manifest.data_dir / ".ingest_cache"
        cache = IngestCache(spill, self.hostname, "netscan")
        count = 0

        for raw in stream_ndjson(path, normalize_record):
            pid = raw.get("pid")
            foreign = raw.get("foreign_addr") or raw.get("foreign_address")
            if pid is None or _skip_addr(str(foreign) if foreign else None):
                continue
            cache.add(
                {
                    "pid": int(pid),
                    "hostname": self.hostname,
                    "address": str(foreign).split(":")[0],
                    "local_addr": raw.get("local_addr"),
                    "local_port": raw.get("local_port"),
                    "foreign_port": raw.get("foreign_port"),
                    "protocol": raw.get("protocol") or raw.get("proto"),
                    "state": raw.get("state"),
                    "created": raw.get("created") or raw.get("create_time"),
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
                WITH r, head(collect(p)) AS proc
                MERGE (ip:IPAddress {address: r.address})
                SET ip.id = r.address
                MERGE (proc)-[c:CONNECTED_TO]->(ip)
                SET c.localAddr = r.local_addr, c.localPort = r.local_port,
                    c.foreignPort = r.foreign_port, c.protocol = r.protocol,
                    c.state = r.state, c.created = r.created, c.source = 'vol_netscan'
                """,
                batch,
            )

        return count
