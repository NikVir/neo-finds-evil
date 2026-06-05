"""Tests for case-scoped investigation and Neo4j path helpers."""

from __future__ import annotations

from pathlib import Path

from forensics.case import CaseManifest
from forensics.case_paths import (
    investigation_dir,
    investigation_l3_path,
    sanitize_neo4j_database,
)


def test_sanitize_neo4j_database() -> None:
    assert sanitize_neo4j_database("rocba-001") == "rocba001"
    assert sanitize_neo4j_database("Case_B") == "caseb"
    assert sanitize_neo4j_database("") == "neo4j"


def test_investigation_dir_default(tmp_path: Path) -> None:
    p = investigation_dir("my-case-001", tmp_path)
    assert p == tmp_path / "investigation" / "my-case-001"


def test_investigation_dir_override(tmp_path: Path) -> None:
    p = investigation_dir("x", tmp_path, override="custom/inv")
    assert p == tmp_path / "custom" / "inv"


def test_investigation_l3_path() -> None:
    assert investigation_l3_path("rocba-001", "001_foo") == (
        "investigation/rocba-001/steps/001_foo"
    )


def test_case_manifest_neo4j_database(tmp_path: Path) -> None:
    case_yaml = tmp_path / "config" / "cases" / "test.yaml"
    case_yaml.parent.mkdir(parents=True)
    case_yaml.write_text(
        """
case_id: test-001
title: Test
case_type: intrusion
brief: brief.md
playbook: intrusion
neo4j:
  database: customdb
hosts: []
"""
    )
    root = tmp_path
    (root / "brief.md").write_text("# brief")
    cm = CaseManifest.from_yaml(case_yaml, project_root=root)
    assert cm.neo4j_database() == "customdb"
    assert cm.case_id == "test-001"


def test_sync_host_case_ids(tmp_path: Path) -> None:
    host_yaml = tmp_path / "host.yaml"
    host_yaml.write_text(
        """
hostname: H1
case_id: old-id
data_dir: /tmp
artifacts:
  pslist: "{hostname}_pslist.json"
"""
    )
    case_yaml = tmp_path / "case.yaml"
    case_yaml.write_text(
        """
case_id: new-001
title: T
case_type: intrusion
brief: brief.md
playbook: intrusion
hosts: [host.yaml]
"""
    )
    (tmp_path / "brief.md").write_text("# b")
    cm = CaseManifest.from_yaml(case_yaml, project_root=tmp_path)
    hosts = cm.sync_host_case_ids()
    assert hosts[0].case_id == "new-001"
