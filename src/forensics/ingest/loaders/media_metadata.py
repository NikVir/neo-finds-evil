"""Ingest exiftool JSONL -> MediaAsset and GeoLocation nodes."""

from __future__ import annotations

from forensics.cache import IngestCache, stream_ndjson
from forensics.ingest.loaders.base import OptionalLoader
from forensics.normalize import normalize_record
from forensics.timestamps import normalize_timestamp


def _gps_coord(tags: dict, key: str) -> float | None:
    val = tags.get(key)
    if val is None:
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


class MediaMetadataLoader(OptionalLoader):
    name = "media_exif"

    def load(self) -> int:
        path = self.path()
        if not path.exists() or path.stat().st_size == 0:
            return 0

        spill = self.manifest.spill_dir or self.manifest.data_dir / ".ingest_cache"
        cache = IngestCache(spill, self.hostname, "media_exif")
        count = 0
        for raw in stream_ndjson(path, normalize_record):
            tags = raw.get("tags") or raw
            if not isinstance(tags, dict):
                tags = raw
            fpath = str(
                tags.get("FileName") or tags.get("SourceFile") or raw.get("source_file") or ""
            )
            if not fpath:
                continue
            lat = _gps_coord(tags, "GPSLatitude") or _gps_coord(tags, "Composite:GPSLatitude")
            lon = _gps_coord(tags, "GPSLongitude") or _gps_coord(tags, "Composite:GPSLongitude")
            taken = normalize_timestamp(
                tags.get("DateTimeOriginal") or tags.get("CreateDate") or tags.get("ModifyDate")
            )
            asset_id = f"{self.hostname}:media:{fpath}"
            cache.add(
                {
                    "id": asset_id,
                    "path": fpath,
                    "hostname": self.hostname,
                    "taken_at": taken,
                    "latitude": lat,
                    "longitude": lon,
                    "camera": str(tags.get("Model") or tags.get("CameraModelName") or ""),
                }
            )
            count += 1

        cache.flush()
        for batch in cache.iter_batches():
            self.client.run_batched(
                """
                UNWIND $rows AS r
                MERGE (h:Host {hostname: r.hostname})
                MERGE (m:MediaAsset {id: r.id})
                SET m.path = r.path, m.takenAt = r.taken_at,
                    m.latitude = r.latitude, m.longitude = r.longitude,
                    m.camera = r.camera
                MERGE (m)-[:STORED_ON]->(h)
                """,
                batch,
            )
            geo_rows = [
                r for r in batch if r.get("latitude") is not None and r.get("longitude") is not None
            ]
            if geo_rows:
                self.client.run_batched(
                    """
                    UNWIND $rows AS r
                    WITH r,
                         round(r.latitude * 1000) / 1000 AS lat,
                         round(r.longitude * 1000) / 1000 AS lon
                    MERGE (g:GeoLocation {id: r.hostname + ':geo:' + toString(lat) + ':' + toString(lon)})
                    SET g.latitude = lat, g.longitude = lon,
                        g.label = toString(lat) + ',' + toString(lon)
                    MATCH (m:MediaAsset {id: r.id})
                    MERGE (m)-[:CAPTURED_AT]->(g)
                    """,
                    geo_rows,
                )
        return count
