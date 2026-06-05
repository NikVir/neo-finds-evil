"""Base loader with optional artifact handling."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from forensics.manifest import HostManifest
from forensics.neo4j_client import Neo4jClient
from forensics.registry import ArtifactCheck, ArtifactStatus, IngestReport


class BaseLoader(ABC):
    name: str
    required: bool = False

    def __init__(self, manifest: HostManifest, client: Neo4jClient) -> None:
        self.manifest = manifest
        self.client = client
        self.hostname = manifest.hostname

    def path(self) -> Path:
        return self.manifest.artifact_path(self.name)

    def check(self) -> ArtifactCheck:
        from forensics.registry import check_artifact

        return check_artifact(self.path(), self.required)

    @abstractmethod
    def load(self) -> int:
        """Return rows ingested."""
        ...


class OptionalLoader(BaseLoader):
    required = False

    def try_load(self, report: IngestReport) -> int:
        check = self.check()
        report.artifacts.append(check)
        if check.status not in (ArtifactStatus.READY,):
            check.reason = check.reason or check.status.value
            return 0
        try:
            rows = self.load()
            check.status = ArtifactStatus.LOADED
            check.rows = rows
            # Surface any de-duplication collapse stats the loader recorded
            # (currently only the evtx loader) so the compression is visible
            # in the ingest report rather than silent.
            stats = getattr(self, "dedup_stats", None)
            if stats:
                check.dedup = stats
            return rows
        except Exception as exc:
            check.status = ArtifactStatus.FAILED
            check.reason = str(exc)
            raise
