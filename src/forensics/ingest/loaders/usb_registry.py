"""Ingest USB device registry JSONL -> USBDevice nodes."""

from __future__ import annotations

from forensics.cache import IngestCache, stream_ndjson
from forensics.ingest.loaders.base import OptionalLoader
from forensics.normalize import normalize_record
from forensics.timestamps import normalize_timestamp


class UsbRegistryLoader(OptionalLoader):
    name = "usb"

    def load(self) -> int:
        path = self.path()
        if not path.exists() or path.stat().st_size == 0:
            return 0

        spill = self.manifest.spill_dir or self.manifest.data_dir / ".ingest_cache"
        cache = IngestCache(spill, self.hostname, "usb")
        count = 0
        for raw in stream_ndjson(path, normalize_record):
            device_id = str(
                raw.get("device_id")
                or raw.get("serial")
                or raw.get("usb_id")
                or raw.get("key")
                or ""
            )
            if not device_id:
                continue
            node_id = f"{self.hostname}:usb:{device_id}"
            cache.add(
                {
                    "id": node_id,
                    "hostname": self.hostname,
                    "device_id": device_id,
                    "friendly_name": str(raw.get("friendly_name") or raw.get("description") or ""),
                    "vendor": str(raw.get("vendor") or raw.get("manufacturer") or ""),
                    "first_seen": normalize_timestamp(
                        raw.get("first_insert") or raw.get("first_seen")
                    ),
                    "last_seen": normalize_timestamp(
                        raw.get("last_insert") or raw.get("last_seen")
                    ),
                }
            )
            count += 1

        cache.flush()
        for batch in cache.iter_batches():
            self.client.run_batched(
                """
                UNWIND $rows AS r
                MERGE (h:Host {hostname: r.hostname})
                MERGE (u:USBDevice {id: r.id})
                SET u.deviceId = r.device_id, u.friendlyName = r.friendly_name,
                    u.vendor = r.vendor, u.firstSeen = r.first_seen,
                    u.lastSeen = r.last_seen
                MERGE (u)-[:PLUGGED_INTO]->(h)
                """,
                batch,
            )
        return count
