"""Tests for progressive ingest tiers."""

from __future__ import annotations

from forensics.ingest.tiers import (
    DEFAULT_TIER,
    resolve_tier_plan,
    tier_for_artifacts,
    triage_playbook_steps,
)


def test_default_tier_is_triage() -> None:
    assert DEFAULT_TIER == "triage"


def test_triage_intrusion_artifacts() -> None:
    plan = resolve_tier_plan("triage", "intrusion")
    assert plan.artifacts == frozenset({"pslist", "netscan", "evtx"})
    assert "sysmon_core" in (plan.evtx_packs or frozenset())


def test_execution_cumulative() -> None:
    plan = resolve_tier_plan("execution", "intrusion")
    assert "shimcache" in plan.artifacts
    assert "pslist" in plan.artifacts
    assert "bulk" not in plan.artifacts


def test_full_tier_all_artifacts() -> None:
    plan = resolve_tier_plan("full", "intrusion", full=True)
    assert plan.is_full
    assert "bulk" in plan.artifacts
    assert plan.evtx_packs is None


def test_account_compromise_triage_packs() -> None:
    plan = resolve_tier_plan("triage", "account_compromise")
    assert plan.evtx_packs == frozenset({"security_auth"})


def test_tier_for_artifacts_filesystem() -> None:
    assert tier_for_artifacts(frozenset({"path_catalog"})) == "filesystem"


def test_triage_playbook_steps_intrusion() -> None:
    steps = triage_playbook_steps("intrusion")
    assert "baseline_summary" in steps
    assert "lateral_logons" in steps
