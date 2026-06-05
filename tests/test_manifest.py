"""Tests for host manifest and optional artifacts."""

from pathlib import Path

from forensics.manifest import HostManifest, discover_hosts
from forensics.registry import ArtifactStatus, check_artifact


def test_manifest_resolve(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    m = HostManifest(
        hostname="TestHost",
        case_id="case-1",
        data_dir=data_dir,
        artifacts={"pslist": "{hostname}_pslist.json"},
    )
    p = m.artifact_path("pslist")
    assert p == data_dir / "TestHost_pslist.json"


def test_check_optional_missing(tmp_path: Path) -> None:
    p = tmp_path / "missing.json"
    c = check_artifact(p, required=False)
    assert c.status == ArtifactStatus.SKIPPED_MISSING


def test_discover_hosts(tmp_path: Path) -> None:
    (tmp_path / "Alpha_pslist.json").write_text("{}\n")
    (tmp_path / "Beta_pslist.json").write_text("{}\n")
    hosts = discover_hosts(tmp_path)
    assert set(hosts) == {"Alpha", "Beta"}
