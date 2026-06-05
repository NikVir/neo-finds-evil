"""Tests for hunt dependency checks."""

from __future__ import annotations

from forensics.hunt_deps import check_hunt_deps, minimum_tier_for_hunt


def test_lateral_logons_needs_evtx() -> None:
    dep = check_hunt_deps("lateral_logons", {"pslist"})
    assert not dep.satisfied
    assert "evtx" in dep.missing_required
    assert dep.suggested_tier == "triage"


def test_lateral_logons_satisfied() -> None:
    dep = check_hunt_deps("lateral_logons", {"pslist", "evtx"})
    assert dep.satisfied


def test_path_discover_needs_filesystem() -> None:
    dep = check_hunt_deps("path_discover", {"pslist", "evtx"})
    assert not dep.satisfied
    assert dep.suggested_tier == "filesystem"


def test_bulk_minimum_tier() -> None:
    assert minimum_tier_for_hunt("bulk_exfil_signals") == "exfil"
