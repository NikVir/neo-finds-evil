"""Scaffold per-case investigation workspace from case YAML."""

from __future__ import annotations

from pathlib import Path

import yaml

from forensics.case import CaseManifest
from forensics.case_paths import investigation_dir
from forensics.investigation_index import render_index_md, shared_investigation_root

CASE_REPORT_TEMPLATE = "CASE_REPORT.template.md"
PHASE2_TEMPLATE = "PHASE2.template.md"


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def init_case_from_manifest(case: CaseManifest, root: Path | None = None) -> Path:
    """Create investigation/<case_id>/ with INDEX, CASE_REPORT, PHASE2, steps/, graphs/."""
    root = root or case.project_root or project_root()
    case_id = case.case_id
    cdir = investigation_dir(case_id, root, override=case.investigation_dir_override or None)
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "steps").mkdir(exist_ok=True)
    (cdir / "graphs").mkdir(exist_ok=True)

    idx = cdir / "INDEX.yaml"
    if not idx.exists():
        idx.write_text(
            yaml.safe_dump(
                {
                    "case_id": case_id,
                    "pass": 1,
                    "status": "not_started",
                    "notes": "",
                    "steps": [],
                },
                sort_keys=False,
            )
        )

    report = cdir / "CASE_REPORT.md"
    if not report.exists():
        tpl_path = shared_investigation_root(root) / CASE_REPORT_TEMPLATE
        if tpl_path.exists():
            report.write_text(tpl_path.read_text().replace("{{case_id}}", case_id))
        else:
            report.write_text(f"# Case report — {case_id}\n\n**Status:** In progress\n")

    rel_config = _relative_case_config(case, root)
    host_paths = [_relative_host_path(h, root) for h in case.hosts]
    phase2 = cdir / "PHASE2.md"
    phase2.write_text(
        _render_phase2_md(
            case_id=case_id,
            title=case.title,
            case_config=rel_config,
            hosts=host_paths,
            neo4j_database=case.neo4j_database(),
            neo4j_uri=case.neo4j_uri(),
            investigation_dir=str(cdir.relative_to(root)),
            root=root,
        )
    )

    render_index_md(case_id, root=root)
    return cdir


def _relative_case_config(case: CaseManifest, root: Path) -> str:
    if case.config_path:
        try:
            return str(case.config_path.relative_to(root))
        except ValueError:
            return str(case.config_path)
    return f"config/cases/{case.case_id}.yaml"


def _relative_host_path(host: Path, root: Path) -> str:
    try:
        return str(host.relative_to(root))
    except ValueError:
        return str(host)


def _hosts_block(hosts: list[str], case_config: str) -> str:
    if not hosts:
        return (
            f"# Add hosts to case YAML, then:\n"
            f"uv run forensics-ingest run -m config/hosts/host.example.yaml -c {case_config}"
        )
    return "\n".join(f"uv run forensics-ingest run -m {h} -c {case_config}" for h in hosts)


def _render_phase2_md(
    *,
    case_id: str,
    title: str,
    case_config: str,
    hosts: list[str],
    neo4j_database: str,
    neo4j_uri: str,
    investigation_dir: str,
    root: Path,
) -> str:
    tpl_path = shared_investigation_root(root) / PHASE2_TEMPLATE
    if tpl_path.exists():
        text = tpl_path.read_text()
        return (
            text.replace("{{case_id}}", case_id)
            .replace("{{title}}", title or case_id)
            .replace("{{case_config}}", case_config)
            .replace("{{neo4j_database}}", neo4j_database)
            .replace("{{neo4j_uri}}", neo4j_uri)
            .replace("{{hosts_block}}", _hosts_block(hosts, case_config))
            .replace("{{investigation_dir}}", investigation_dir)
        )

    return f"""# Phase 2 runbook — {case_id}

**Title:** {title or case_id}
**Case config:** `{case_config}`
**Investigation dir:** `{investigation_dir}/`

## Ingest

```bash
bash scripts/run-phase2-case.sh --fresh -c {case_config}
```

{_hosts_block(hosts, case_config)}
"""
