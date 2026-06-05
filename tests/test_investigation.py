"""Tests for forensics case init and investigation index."""

from __future__ import annotations

from pathlib import Path

from forensics.case_init import init_case_from_manifest
from forensics.case import CaseManifest
from forensics.investigation_index import (
    close_step,
    list_cases,
    open_step,
    render_index_md,
)


def _write_case_yaml(tmp_path: Path, case_id: str = "test-case-001") -> Path:
    hosts_dir = tmp_path / "config" / "hosts"
    hosts_dir.mkdir(parents=True, exist_ok=True)
    host = hosts_dir / "host-a.yaml"
    if not host.exists():
        host.write_text(
            "hostname: host-a\ndata_dir: /tmp/data\nplaso_store: /tmp/plaso.plaso\n"
        )
    cases_dir = tmp_path / "config" / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)
    inv_shared = tmp_path / "investigation"
    inv_shared.mkdir(exist_ok=True)
    if not (inv_shared / "CASE_REPORT.template.md").exists():
        (inv_shared / "CASE_REPORT.template.md").write_text("# Case report — {{case_id}}\n")
        (inv_shared / "PHASE2.template.md").write_text(
            "# Phase 2 — {{case_id}}\n{{case_config}}\n{{hosts_block}}\n"
        )
        (inv_shared / "review.template.md").write_text(
            "# {{step_id}}\n{{hypothesis}}\n{{expected_outcome}}\n"
        )
    case_path = cases_dir / f"{case_id}.yaml"
    case_path.write_text(
        f"""case_id: {case_id}
title: Test
case_type: intrusion
brief: docs/cases/brief.md
playbook: intrusion
hosts:
  - config/hosts/host-a.yaml
neo4j:
  database: testcase001
"""
    )
    return case_path


def test_init_case_creates_structure(tmp_path: Path) -> None:
    case_path = _write_case_yaml(tmp_path)
    case = CaseManifest.from_yaml(case_path, project_root=tmp_path)
    cdir = init_case_from_manifest(case, root=tmp_path)
    assert cdir == tmp_path / "investigation" / "test-case-001"
    assert (cdir / "INDEX.yaml").exists()
    assert (cdir / "CASE_REPORT.md").exists()
    assert (cdir / "PHASE2.md").exists()
    assert (cdir / "steps").is_dir()
    assert (cdir / "graphs").is_dir()


def test_open_close_step_under_case_dir(tmp_path: Path) -> None:
    case_path = _write_case_yaml(tmp_path, case_id="case-a")
    case = CaseManifest.from_yaml(case_path, project_root=tmp_path)
    init_case_from_manifest(case, root=tmp_path)

    sdir = open_step(
        "001_baseline",
        case_id="case-a",
        hypothesis="test hyp",
        expected_outcome="rows",
        root=tmp_path,
    )
    assert sdir == tmp_path / "investigation" / "case-a" / "steps" / "001_baseline"
    assert (sdir / "review.md").exists()

    close_step(
        "001_baseline",
        case_id="case-a",
        outcome="inconclusive",
        one_line="baseline ok",
        root=tmp_path,
    )

    idx = (tmp_path / "investigation" / "case-a" / "INDEX.yaml").read_text()
    assert "001_baseline" in idx
    assert "investigation/case-a/steps/001_baseline" in idx

    md_path = render_index_md("case-a", root=tmp_path)
    assert md_path.exists()
    assert "case-a" in md_path.read_text()


def test_list_cases(tmp_path: Path) -> None:
    for cid in ("alpha", "beta"):
        case_path = _write_case_yaml(tmp_path, case_id=cid)
        case = CaseManifest.from_yaml(case_path, project_root=tmp_path)
        init_case_from_manifest(case, root=tmp_path)
    cases = list_cases(tmp_path)
    assert "alpha" in cases
    assert "beta" in cases
