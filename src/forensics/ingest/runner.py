"""Orchestrate ingest loaders with optional artifact skips."""

from __future__ import annotations

import os

from forensics.ingest.loaders import (
    BulkExtractorLoader,
    DlllistLoader,
    MediaMetadataLoader,
    MftLazyLoader,
    NetscanLoader,
    PathCatalogLoader,
    PrefetchLoader,
    PslistLoader,
    ShimcacheLoader,
    UsbRegistryLoader,
    WinevtxLoader,
)
from forensics.ingest.loaders.base import BaseLoader, OptionalLoader
from forensics.ingest.loaders.pslist import PslistLoader as RequiredPslist
from forensics.case import CaseManifest
from forensics.manifest import HostManifest
from forensics.neo4j_client import Neo4jClient
from forensics.correlate import run_correlation
from forensics.correlate_artifacts import run_artifact_correlation
from forensics.ingest.tiers import DEFAULT_TIER, resolve_tier_plan
from forensics.registry import ArtifactStatus, IngestReport

ARTIFACT_CORRELATION_SOURCES = frozenset({"shimcache", "prefetch", "bulk"})

SKIP_IF_LOADED_ARTIFACTS = frozenset({"evtx", "bulk", "shimcache", "prefetch"})

LOADER_ORDER: list[type[BaseLoader]] = [
    PslistLoader,
    DlllistLoader,
    NetscanLoader,
    WinevtxLoader,
    ShimcacheLoader,
    PrefetchLoader,
    PathCatalogLoader,
    MftLazyLoader,
    MediaMetadataLoader,
    UsbRegistryLoader,
    BulkExtractorLoader,
]


def run_ingest(
    manifest: HostManifest,
    client: Neo4jClient,
    only: set[str] | None = None,
    case: CaseManifest | None = None,
    *,
    tier: str | None = None,
    full: bool = False,
    skip_correlation: bool = False,
    skip_if_loaded: bool = True,
    force_reload: bool = False,
) -> IngestReport:
    report = IngestReport(hostname=manifest.hostname)
    # Schema is idempotent (CREATE ... IF NOT EXISTS), but N parallel workers all
    # ensuring it at once can throw transient errors. rebuild-case ensures it once
    # up front and sets FORENSICS_SCHEMA_READY=1 so children skip the storm.
    if os.environ.get("FORENSICS_SCHEMA_READY") != "1":
        client.ensure_schema()

    case_type = case.case_type if case else "intrusion"
    profile_override = manifest.event_profile or ""
    explicit_only = only is not None and only == {"bulk"}
    resolved_tier = "full" if full else (tier or DEFAULT_TIER)
    plan = resolve_tier_plan(
        resolved_tier,
        case_type,
        event_profile_override=profile_override,
        only=only,
        full=full,
    )
    if only is None:
        only = set(plan.artifacts)
    report.ingest_tier = plan.tier

    for loader_cls in LOADER_ORDER:
        name = loader_cls.name
        if only and name not in only:
            continue
        loader = loader_cls(manifest, client)
        if case and hasattr(loader, "set_case"):
            loader.set_case(case)
        if plan and name == "evtx" and hasattr(loader, "set_evtx_packs"):
            loader.set_evtx_packs(plan.evtx_packs)
        if hasattr(loader, "set_ingest_tier") and plan:
            loader.set_ingest_tier(plan.tier, explicit_only=explicit_only)
        if (
            skip_if_loaded
            and not force_reload
            and name in SKIP_IF_LOADED_ARTIFACTS
            and _artifact_already_loaded(client, manifest.hostname, name)
        ):
            check = loader.check()
            check.status = ArtifactStatus.SKIPPED
            check.reason = f"{name} already in graph (use --force-reload to re-ingest)"
            report.artifacts.append(check)
            continue
        if isinstance(loader, RequiredPslist) or loader.required:
            check = loader.check()
            report.artifacts.append(check)
            if check.status != ArtifactStatus.READY:
                if os.environ.get("ALLOW_MISSING_PSLIST") == "1":
                    check.reason = f"{check.reason} (skipped: ALLOW_MISSING_PSLIST=1)"
                    continue
                raise FileNotFoundError(f"Required artifact {name}: {check.reason}")
            check.rows = loader.load()
            check.status = ArtifactStatus.LOADED
        elif isinstance(loader, OptionalLoader):
            loader.try_load(report)

    loaded_evtx = any(
        a.name == "evtx" and a.status == ArtifactStatus.LOADED for a in report.artifacts
    )
    if loaded_evtx and not skip_correlation:
        report.correlation = run_correlation(manifest.hostname, client)

    loaded_artifacts = any(
        a.name in ARTIFACT_CORRELATION_SOURCES and a.status == ArtifactStatus.LOADED
        for a in report.artifacts
    )
    if loaded_artifacts and not skip_correlation:
        report.artifact_correlation = run_artifact_correlation(manifest.hostname, client, case=case)

    return report


def _artifact_already_loaded(client: Neo4jClient, hostname: str, artifact: str) -> bool:
    if artifact == "evtx":
        return client.host_has_events(hostname)
    if artifact == "bulk":
        rows = client.query(
            """
            MATCH (h:Host {hostname: $hostname})-[:REFERENCED {source: 'bulk_extractor'}]->()
            RETURN count(*) AS c LIMIT 1
            """,
            {"hostname": hostname},
        )
        return bool(rows and int(rows[0].get("c") or 0) > 0)
    if artifact in ("shimcache", "prefetch"):
        rows = client.query(
            """
            MATCH (h:Host {hostname: $hostname})-[ex:EXECUTED {source: $source}]->(:File)
            RETURN count(ex) AS c LIMIT 1
            """,
            {"hostname": hostname, "source": artifact},
        )
        return bool(rows and int(rows[0].get("c") or 0) > 0)
    return False
