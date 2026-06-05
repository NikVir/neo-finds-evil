"""Bulk-extractor features (email/url) — case-gated optional ingest."""

from __future__ import annotations

from forensics.cache import IngestCache, stream_ndjson
from forensics.case import CaseManifest
from forensics.ingest.loaders.base import OptionalLoader
from forensics.normalize import normalize_record
from forensics.path_normalize import normalized_file_id
from forensics.registry import ArtifactCheck, ArtifactStatus, check_artifact


def bulk_enabled_for_case(case: CaseManifest) -> bool:
    """Whether bulk extraction is enabled at case level (ignores ingest tier)."""
    enrichment = getattr(case, "enrichment", None) or {}
    if not isinstance(enrichment, dict):
        return False
    mode = str(enrichment.get("bulk_extractor", "false")).lower()
    if mode == "false":
        return False
    if mode == "true":
        return True
    if mode == "auto":
        bulk_hyps = enrichment.get("bulk_hypotheses") or []
        open_ids = {h.id for h in case.hypotheses if h.status == "open"}
        return any(str(h) in open_ids for h in bulk_hyps)
    return False


def bulk_allowed_for_ingest(
    case: CaseManifest | None,
    tier: str,
    *,
    explicit_only: bool = False,
) -> bool:
    if case is None:
        return False
    enrichment = getattr(case, "enrichment", None) or {}
    if not isinstance(enrichment, dict):
        return False
    mode = str(enrichment.get("bulk_extractor", "false")).lower()
    if mode == "false":
        return False
    if explicit_only:
        return True
    return tier in ("exfil", "full", "custom")


class BulkExtractorLoader(OptionalLoader):
    name = "bulk"
    _case: CaseManifest | None = None
    _ingest_tier: str = "triage"
    _explicit_only: bool = False

    def set_case(self, case: CaseManifest) -> None:
        self._case = case

    def set_ingest_tier(self, tier: str, *, explicit_only: bool = False) -> None:
        self._ingest_tier = tier
        self._explicit_only = explicit_only

    def check(self) -> ArtifactCheck:
        path = self.path()
        if not bulk_allowed_for_ingest(
            self._case, self._ingest_tier, explicit_only=self._explicit_only
        ):
            return ArtifactCheck(
                name=self.name,
                path=path,
                status=ArtifactStatus.SKIPPED,
                reason="bulk requires tier exfil/full or --only bulk (enrichment.bulk_extractor must not be false)",
            )
        return check_artifact(path, required=False)

    def load(self) -> int:
        if not bulk_allowed_for_ingest(
            self._case, self._ingest_tier, explicit_only=self._explicit_only
        ):
            return 0
        path = self.path()
        if not path.exists() or path.stat().st_size == 0:
            return 0

        spill = self.manifest.spill_dir or self.manifest.data_dir / ".ingest_cache"
        cache = IngestCache(spill, self.hostname, "bulk")
        count = 0
        for raw in stream_ndjson(path, normalize_record):
            feature = str(raw.get("feature") or raw.get("type") or "").lower()
            value = str(raw.get("value") or raw.get("email") or raw.get("url") or "").strip()
            if not value:
                continue
            if feature in ("email", "e-mail"):
                cache.add(
                    {
                        "kind": "email",
                        "hostname": self.hostname,
                        "id": value.lower(),
                        "address": value.lower(),
                        "context": str(raw.get("context") or "")[:500],
                    }
                )
                count += 1
            elif feature in ("url", "domain"):
                cache.add(
                    {
                        "kind": "url",
                        "hostname": self.hostname,
                        "id": value.lower()[:512],
                        "url": value[:512],
                        "context": str(raw.get("context") or "")[:500],
                    }
                )
                count += 1
            elif "\\" in value or "/" in value:
                norm, fid = normalized_file_id(self.hostname, value)
                if fid:
                    cache.add(
                        {
                            "kind": "path",
                            "hostname": self.hostname,
                            "file_id": fid,
                            "path": norm,
                            "name": norm.split("\\")[-1],
                            "context": str(raw.get("context") or "")[:500],
                        }
                    )
                    count += 1

        cache.flush()
        for batch in cache.iter_batches():
            emails = [r for r in batch if r.get("kind") == "email"]
            urls = [r for r in batch if r.get("kind") == "url"]
            paths = [r for r in batch if r.get("kind") == "path"]
            if emails:
                self.client.run_batched(
                    """
                    UNWIND $rows AS r
                    MERGE (h:Host {hostname: r.hostname})
                    MERGE (e:EmailAddress {id: r.id})
                    SET e.address = r.address, e.source = 'bulk_extractor', e.context = r.context
                    MERGE (h)-[:REFERENCED {source: 'bulk_extractor'}]->(e)
                    """,
                    emails,
                )
            if urls:
                self.client.run_batched(
                    """
                    UNWIND $rows AS r
                    MERGE (h:Host {hostname: r.hostname})
                    MERGE (u:URL {id: r.id})
                    SET u.url = r.url, u.source = 'bulk_extractor', u.context = r.context
                    MERGE (h)-[:REFERENCED {source: 'bulk_extractor'}]->(u)
                    """,
                    urls,
                )
            if paths:
                self.client.run_batched(
                    """
                    UNWIND $rows AS r
                    MERGE (h:Host {hostname: r.hostname})
                    MERGE (f:File {id: r.file_id})
                    SET f.path = r.path, f.name = r.name, f.source = 'bulk_extractor'
                    MERGE (h)-[:REFERENCED {source: 'bulk_extractor'}]->(f)
                    """,
                    paths,
                )
        return count
