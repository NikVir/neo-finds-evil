"""Host manifest loading and path resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class HostManifest:
    hostname: str
    case_id: str = ""
    data_dir: Path = field(default_factory=Path)
    plaso_store: Path | None = None
    spill_dir: Path | None = None
    evidence_e01: Path | None = None
    evidence_memory: Path | None = None
    event_profile: str = ""
    artifacts: dict[str, str] = field(default_factory=dict)

    def resolve(self, template: str) -> Path:
        p = Path(
            template.format(
                hostname=self.hostname,
                data_dir=str(self.data_dir),
            )
        )
        if not p.is_absolute() and "data_dir" not in template:
            return self.data_dir / p
        return p

    def artifact_path(self, name: str) -> Path:
        if name not in self.artifacts:
            raise KeyError(f"Unknown artifact: {name}")
        return self.resolve(self.artifacts[name])

    @classmethod
    def from_yaml(cls, path: Path) -> HostManifest:
        raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
        data_dir = Path(str(raw.get("data_dir", ".")))
        spill = raw.get("spill_dir")
        plaso = raw.get("plaso_store")
        e01 = raw.get("evidence_e01")
        mem = raw.get("evidence_memory")
        return cls(
            hostname=str(raw["hostname"]),
            case_id=str(raw.get("case_id", "")),
            data_dir=data_dir,
            plaso_store=Path(plaso.format(data_dir=str(data_dir))) if plaso else None,
            spill_dir=Path(spill.format(data_dir=str(data_dir)))
            if spill
            else data_dir / ".ingest_cache",
            evidence_e01=Path(str(e01)) if e01 else None,
            evidence_memory=Path(str(mem)) if mem else None,
            event_profile=str(raw.get("event_profile", "")),
            artifacts={k: str(v) for k, v in (raw.get("artifacts") or {}).items()},
        )


def discover_hosts(data_dir: Path) -> list[str]:
    """Find hostnames from *_pslist.json in data_dir."""
    hosts: list[str] = []
    for p in sorted(data_dir.glob("*_pslist.json")):
        name = p.name[: -len("_pslist.json")]
        if name:
            hosts.append(name)
    return hosts
