"""Artifact availability and ingest status."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ArtifactStatus(str, Enum):
    READY = "ready"
    SKIPPED_MISSING = "skipped_missing"
    SKIPPED_EMPTY = "skipped_empty"
    LOADED = "loaded"
    FAILED = "failed"
    SKIPPED = "skipped"


REQUIRED_ARTIFACTS = frozenset({"pslist"})
OPTIONAL_ARTIFACTS = frozenset(
    {
        "dlllist",
        "netscan",
        "evtx",
        "shimcache",
        "prefetch",
        "path_catalog",
        "mft",
        "media_exif",
        "usb",
        "bulk",
    }
)

CASE_ARTIFACT_PROFILES: dict[str, dict[str, frozenset[str]]] = {
    "intrusion": {
        "required": frozenset({"pslist"}),
        "recommended": frozenset({"netscan", "evtx", "dlllist", "shimcache", "prefetch"}),
    },
    "insider_ip_theft": {
        "required": frozenset({"pslist", "evtx"}),
        "recommended": frozenset(
            {
                "path_catalog",
                "mft",
                "netscan",
                "dlllist",
                "media_exif",
                "usb",
                "shimcache",
                "prefetch",
            }
        ),
    },
    "account_compromise": {
        "required": frozenset({"pslist", "evtx"}),
        "recommended": frozenset({"netscan", "mft"}),
    },
    "hybrid": {
        "required": frozenset({"pslist", "evtx"}),
        "recommended": frozenset({"netscan", "mft", "dlllist"}),
    },
}


INGEST_TIERS = ("triage", "execution", "filesystem", "exfil", "full")


def case_coverage_notes(case_type: str, report: IngestReport) -> list[str]:
    """Return human-readable coverage gaps for a case type."""
    profile = CASE_ARTIFACT_PROFILES.get(case_type, CASE_ARTIFACT_PROFILES["intrusion"])
    loaded = {a.name for a in report.artifacts if a.status == ArtifactStatus.LOADED}
    notes: list[str] = []
    for name in profile["required"]:
        if name not in loaded:
            notes.append(f"REQUIRED missing or not loaded: {name}")
    for name in profile["recommended"]:
        if name not in loaded:
            notes.append(f"recommended not loaded: {name}")
    tier = getattr(report, "ingest_tier", "triage")
    if tier != "full":
        notes.append(f"progressive ingest tier: {tier} (escalate with load-tier or --full)")
    return notes


@dataclass
class ArtifactCheck:
    name: str
    path: Path
    status: ArtifactStatus
    reason: str = ""
    rows: int = 0
    # Per-class first-occurrence-per-tuple collapse stats (evtx only), e.g.
    # [{event_id, label, keys, kept, dropped, unique}]. None when no dedup ran.
    dedup: list[dict] | None = None


@dataclass
class IngestReport:
    hostname: str
    artifacts: list[ArtifactCheck] = field(default_factory=list)
    correlation: dict | None = None
    artifact_correlation: dict | None = None
    ingest_tier: str = "triage"

    def to_dict(self) -> dict:
        out = {
            "hostname": self.hostname,
            "artifacts": [
                {
                    "name": a.name,
                    "path": str(a.path),
                    "status": a.status.value,
                    "reason": a.reason,
                    "rows": a.rows,
                    **({"dedup": a.dedup} if a.dedup else {}),
                }
                for a in self.artifacts
            ],
        }
        if self.correlation:
            out["correlation"] = self.correlation
        if getattr(self, "artifact_correlation", None):
            out["artifact_correlation"] = self.artifact_correlation
        if getattr(self, "ingest_tier", None):
            out["ingest_tier"] = self.ingest_tier
        return out


def check_artifact(path: Path, required: bool) -> ArtifactCheck:
    name = path.stem
    if not path.exists():
        return ArtifactCheck(
            name=name,
            path=path,
            status=ArtifactStatus.FAILED if required else ArtifactStatus.SKIPPED_MISSING,
            reason="file not found",
        )
    if path.stat().st_size == 0:
        return ArtifactCheck(
            name=name,
            path=path,
            status=ArtifactStatus.FAILED if required else ArtifactStatus.SKIPPED_EMPTY,
            reason="empty file",
        )
    return ArtifactCheck(name=name, path=path, status=ArtifactStatus.READY)
