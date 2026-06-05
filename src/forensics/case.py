"""Case manifest loading (above per-host manifests)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from forensics.case_paths import investigation_dir, sanitize_neo4j_database
from forensics.manifest import HostManifest


@dataclass
class Hypothesis:
    id: str
    statement: str
    status: str = "open"


@dataclass
class CaseManifest:
    case_id: str
    title: str
    case_type: str
    brief: Path
    playbook: str
    hosts: list[Path] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    sensitive_paths: list[str] = field(default_factory=list)
    sensitive_extensions: list[str] = field(default_factory=list)
    filename_keywords: list[str] = field(default_factory=list)
    time_window: dict[str, str] = field(default_factory=dict)
    psort_date_filter: str = ""
    discovery: dict[str, object] = field(default_factory=dict)
    media: dict[str, object] = field(default_factory=dict)
    enrichment: dict[str, object] = field(default_factory=dict)
    evtx_dedup: dict[str, object] = field(default_factory=dict)
    investigation_dir_override: str = ""
    neo4j: dict[str, str] = field(default_factory=dict)
    config_path: Path | None = None
    project_root: Path | None = None

    @classmethod
    def from_yaml(cls, path: Path, project_root: Path | None = None) -> CaseManifest:
        root = project_root or path.parent.parent.parent
        raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
        brief = Path(str(raw.get("brief", "")))
        if not brief.is_absolute():
            brief = root / brief
        host_paths = []
        for h in raw.get("hosts") or []:
            hp = Path(str(h))
            host_paths.append(hp if hp.is_absolute() else root / hp)
        hyps = [
            Hypothesis(
                id=str(x["id"]),
                statement=str(x.get("statement", "")),
                status=str(x.get("status", "open")),
            )
            for x in (raw.get("hypotheses") or [])
        ]
        neo4j_raw = raw.get("neo4j") or {}
        neo4j = (
            {str(k): str(v) for k, v in neo4j_raw.items()} if isinstance(neo4j_raw, dict) else {}
        )
        return cls(
            case_id=str(raw["case_id"]),
            title=str(raw.get("title", "")),
            case_type=str(raw.get("case_type", "intrusion")),
            brief=brief,
            playbook=str(raw.get("playbook", "intrusion")),
            hosts=host_paths,
            hypotheses=hyps,
            sensitive_paths=[str(p) for p in (raw.get("sensitive_paths") or [])],
            sensitive_extensions=[str(e) for e in (raw.get("sensitive_extensions") or [])],
            filename_keywords=[str(k) for k in (raw.get("filename_keywords") or [])],
            time_window=dict(raw.get("time_window") or {}),
            psort_date_filter=str(raw.get("psort_date_filter", "")),
            discovery=dict(raw.get("discovery") or {}),
            media=dict(raw.get("media") or {}),
            enrichment=dict(raw.get("enrichment") or {}),
            evtx_dedup=dict(raw.get("evtx_dedup") or {}),
            investigation_dir_override=str(raw.get("investigation_dir", "") or ""),
            neo4j=neo4j,
            config_path=path,
            project_root=root,
        )

    def neo4j_database(self) -> str:
        env_db = os.environ.get("NEO4J_DATABASE")
        if env_db:
            return sanitize_neo4j_database(env_db)
        if self.neo4j.get("database"):
            return sanitize_neo4j_database(self.neo4j["database"])
        return sanitize_neo4j_database(self.case_id)

    def neo4j_uri(self) -> str:
        return self.neo4j.get("uri") or os.environ.get("NEO4J_URI", "bolt://127.0.0.1:7687")

    def investigation_path(self, root: Path | None = None) -> Path:
        r = root or self.project_root or Path(".")
        override = self.investigation_dir_override or None
        return investigation_dir(self.case_id, r, override=override)

    def load_hosts(self) -> list[HostManifest]:
        return [HostManifest.from_yaml(p) for p in self.hosts]

    def sync_host_case_ids(self, hosts: list[HostManifest] | None = None) -> list[HostManifest]:
        """Set each host manifest case_id from this case YAML (ingest-time)."""
        result = hosts if hosts is not None else self.load_hosts()
        for h in result:
            h.case_id = self.case_id
        return result
