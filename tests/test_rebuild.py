"""Unit tests for the rebuild-case orchestration logic.

Covers the pure planning/aggregation helpers and plan construction against the
committed srl-2018 case (read-only). Nothing here touches Neo4j or executes a
rebuild.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import forensics.rebuild as rb
from forensics.case import CaseManifest
from forensics.rebuild import (
    EXCLUDED_HUNTS,
    HEALTH_METRIC_CYPHER,
    HostPlan,
    RebuildPlan,
    aggregate_summary,
    build_plan,
    classify_hunt_result,
    default_workers,
    format_plan,
    hunt_command,
    ingest_command,
    resolve_database,
    rows_in_output,
    select_hunts,
)

_ROOT = Path(__file__).resolve().parents[1]
_CASE = _ROOT / "config" / "cases" / "srl-2018.yaml"

# The srl-2018 case manifest and its per-host YAMLs carry local ingest paths and
# are intentionally NOT shipped in the public package. Tests that parse the real
# case skip cleanly when it is absent (a fresh clone), rather than fail.
_REQUIRES_CASE = pytest.mark.skipif(
    not _CASE.exists(),
    reason=(
        "requires full ingest config (config/cases/srl-2018.yaml + config/hosts/*.yaml, "
        "not shipped in the public package; see docs/evidence-dataset.md pipeline section)"
    ),
)


# --- default_workers --------------------------------------------------------


def test_default_workers_reference_box_is_four():
    assert default_workers(8) == 4  # observed sweet spot, leaves Neo4j headroom


def test_default_workers_never_below_one_and_capped():
    assert default_workers(1) == 1
    assert default_workers(2) == 1
    assert default_workers(64) == 4  # capped
    assert default_workers(8, cap=6) == 4  # min(cap, nproc//2)


# --- resolve_database (caveat 1) -------------------------------------------


def test_resolve_database_defaults_to_neo4j():
    assert resolve_database(None, None) == "neo4j"
    assert resolve_database("", "") == "neo4j"


def test_resolve_database_explicit_request_wins():
    assert resolve_database("srl2018", None) == "srl2018"  # env
    assert resolve_database("env", "cli") == "cli"  # cli over env


# --- select_hunts (caveat 3) -----------------------------------------------


def test_select_hunts_filters_unknowns_preserves_order():
    # summary is no longer excluded (it was rewritten to be fast and re-included);
    # only non-existent hunts are dropped, order preserved.
    playbook = ["summary", "event_coverage", "sysmon_process_spawn", "not_a_hunt"]
    available = {"event_coverage", "sysmon_process_spawn", "summary"}
    assert select_hunts(playbook, available) == [
        "summary",
        "event_coverage",
        "sysmon_process_spawn",
    ]


def test_select_hunts_dedupes():
    playbook = ["dns_queries", "dns_queries", "log_cleared"]
    available = {"dns_queries", "log_cleared"}
    assert select_hunts(playbook, available) == ["dns_queries", "log_cleared"]


def test_select_hunts_exclude_param_still_quarantines():
    # The exclusion mechanism remains for quarantining a future known-bad hunt.
    playbook = ["summary", "event_coverage"]
    available = {"summary", "event_coverage"}
    assert select_hunts(playbook, available, exclude={"summary"}) == ["event_coverage"]


def test_select_hunts_override_replaces_playbook_filtered_to_available():
    out = select_hunts(
        ["event_coverage"], {"event_coverage", "dns_queries"}, override=["dns_queries", "nope"]
    )
    assert out == ["dns_queries"]  # 'nope' not available


def test_excluded_hunts_empty_by_default():
    # summary fixed + re-included; per-hunt timeout is the runtime safety net.
    assert EXCLUDED_HUNTS == frozenset()


# --- classify_hunt_result / rows_in_output ---------------------------------


def test_classify_hunt_result_matrix():
    assert classify_hunt_result(0, False, 5) == "pass"
    assert classify_hunt_result(0, False, 0) == "empty"
    assert classify_hunt_result(1, False, None) == "fail"
    assert classify_hunt_result(0, False, None) == "fail"  # unparseable output
    assert classify_hunt_result(None, True, None) == "timeout"


def test_rows_in_output():
    assert rows_in_output({"rows": [1, 2, 3]}) == 3
    assert rows_in_output({"rows": []}) == 0
    assert rows_in_output({"error": "boom"}) is None
    assert rows_in_output(None) is None
    assert rows_in_output({"no_rows_key": 1}) is None


# --- command construction ---------------------------------------------------


def _plan(**over) -> RebuildPlan:
    base = dict(
        case_id="c",
        case_config=Path("config/cases/c.yaml"),
        database="neo4j",
        tier="execution",
        workers=4,
        hunt_timeout=150,
        ingest_retries=1,
        hosts=[HostPlan("H1", Path("config/hosts/h1.yaml"), Path("/d/.ingest_cache"), True)],
        hunts=["event_coverage"],
        wipe_caches=["/d/.ingest_cache"],
        investigation_dir=Path("investigation/c"),
        hunts_dir=Path("investigation/c/hunts"),
        log_path=Path("investigation/c/rebuild.log"),
        summary_path=Path("investigation/c/rebuild-summary.json"),
    )
    base.update(over)
    return RebuildPlan(**base)


def test_ingest_command_targets_cli_module_with_tier():
    plan = _plan()
    cmd = ingest_command(plan, plan.hosts[0])
    assert cmd[1:4] == ["-m", "forensics.cli", "run"]
    assert "--tier" in cmd and "execution" in cmd
    assert str(plan.hosts[0].manifest_path) in cmd


def test_hunt_command_targets_cli_module():
    cmd = hunt_command(_plan(), "dns_queries")
    assert cmd[1:5] == ["-m", "forensics.cli", "hunt", "dns_queries"]


def test_health_metric_targets_sysmon_spawned():
    assert "SPAWNED {source: 'sysmon'}" in HEALTH_METRIC_CYPHER


# --- aggregate_summary (caveat 8: dedup surfaced) --------------------------


def test_aggregate_summary_rolls_up_dedup_counts_and_health():
    plan = _plan(hosts=[])
    host_results = [
        {
            "hostname": "SRL-DC",
            "status": "ok",
            "attempts": 1,
            "dedup": [
                {"event_id": 4624, "label": "4624 logons", "kept": 150, "dropped": 1_600_000}
            ],
        },
        {
            "hostname": "SRL-WKSTN05",
            "status": "ok",
            "attempts": 1,
            "dedup": [{"event_id": 3, "label": "sysmon net", "kept": 24, "dropped": 90_000}],
        },
        {"hostname": "SRL-DMZFTP", "status": "failed", "attempts": 2, "dedup": [], "error": "boom"},
    ]
    hunt_results = [
        {"hunt": "event_coverage", "status": "pass", "rows": 30},
        {"hunt": "external_connections", "status": "empty", "rows": 0},
        {"hunt": "x", "status": "timeout", "rows": None},
    ]
    counts = {"SRL-DC": {"events": 137814, "processes": 123}}
    summary = aggregate_summary(plan, host_results, hunt_results, counts, health=595)

    assert summary["dedup"]["total_dropped"] == 1_690_000
    assert {d["event_id"] for d in summary["dedup"]["by_class"]} == {4624, 3}
    assert summary["host_status_counts"] == {"ok": 2, "failed": 1}
    assert summary["hunt_status_counts"] == {"pass": 1, "empty": 1, "fail": 0, "timeout": 1}
    assert summary["health"]["ok"] is True
    # per-host graph counts merged in
    dc = next(h for h in summary["hosts"] if h["hostname"] == "SRL-DC")
    assert dc["events"] == 137814


def test_aggregate_summary_health_false_when_zero_edges():
    summary = aggregate_summary(_plan(hosts=[]), [], [], {}, health=0)
    assert summary["health"]["ok"] is False


# --- build_plan against the real srl-2018 case (read-only) -----------------


def _case() -> CaseManifest:
    return CaseManifest.from_yaml(_CASE, project_root=_ROOT)


@_REQUIRES_CASE
def test_build_plan_parses_all_seven_hosts_and_flags_disk_only():
    plan = build_plan(
        _case(),
        tier="execution",
        workers=4,
        hunt_timeout=150,
        ingest_retries=1,
        database="neo4j",
        hunts_override=None,
        log_path=Path("/tmp/x.log"),
        project_root=_ROOT,
    )
    hostnames = {h.hostname for h in plan.hosts}
    assert len(plan.hosts) == 7
    assert "SRL-DC" in hostnames and "SRL-DMZFTP" in hostnames
    # dmzftp has no memory image -> no pslist json -> flagged disk-only
    dmz = next(h for h in plan.hosts if h.hostname == "SRL-DMZFTP")
    assert dmz.pslist_present is False


@_REQUIRES_CASE
def test_build_plan_selects_intrusion_hunts_including_fixed_summary():
    plan = build_plan(
        _case(),
        tier="execution",
        workers=4,
        hunt_timeout=150,
        ingest_retries=1,
        database="neo4j",
        hunts_override=None,
        log_path=Path("/tmp/x.log"),
        project_root=_ROOT,
    )
    # summary is now fast (per-host CALL subqueries) and re-included
    assert "summary" in plan.hunts
    # the projection-revived hunts must be present
    for h in (
        "sysmon_process_spawn",
        "external_connections",
        "lateral_logons",
        "registry_persistence",
        "sysmon_file_touch",
    ):
        assert h in plan.hunts
    assert "event_coverage" in plan.hunts


@_REQUIRES_CASE
def test_format_plan_is_side_effect_free_text():
    plan = build_plan(
        _case(),
        tier="execution",
        workers=3,
        hunt_timeout=99,
        ingest_retries=2,
        database="neo4j",
        hunts_override=["event_coverage"],
        log_path=Path("/tmp/x.log"),
        project_root=_ROOT,
    )
    text = format_plan(plan)
    assert "REBUILD PLAN" in text
    assert "disk-only" in text  # dmzftp annotation
    assert "dry run" in text.lower()
    assert plan.to_dict()["neo4j_database"] == "neo4j"


# --- VERIFY-step query is anchored (no global multi-OPTIONAL) ---------------


def test_verify_queries_are_per_host_anchored():
    for cypher in (rb._VERIFY_EVENTS_CYPHER, rb._VERIFY_PROCS_CYPHER):
        assert "Host {hostname: $h}" in cypher
        assert "OPTIONAL MATCH" not in cypher
    assert "$h" not in HEALTH_METRIC_CYPHER  # health is a global count-store scan


# --- _graph_counts degrades gracefully, never raises ------------------------


class _FakeNeo4jClient:
    """Stand-in for Neo4jClient: query_guarded returns canned (rows, status)."""

    def __init__(self, *_, timeout_on: str | None = None, **__) -> None:
        self.timeout_on = timeout_on

    def query_guarded(self, cypher, parameters=None, *, timeout=None):
        if self.timeout_on and self.timeout_on in cypher:
            return None, "timeout"
        return [{"c": 42}], "ok"

    def close(self) -> None:
        pass


def _mini_plan(tmp: Path, hosts=("H1", "H2")) -> RebuildPlan:
    return RebuildPlan(
        case_id="srl-2018",
        case_config=_CASE,
        database="neo4j",
        tier="execution",
        workers=1,
        hunt_timeout=10,
        ingest_retries=0,
        hosts=[HostPlan(h, Path(f"{h}.yaml"), Path("/c"), True) for h in hosts],
        hunts=["event_coverage"],
        wipe_caches=[],
        investigation_dir=tmp,
        hunts_dir=tmp / "hunts",
        log_path=tmp / "r.log",
        summary_path=tmp / "summary.json",
    )


def test_graph_counts_ok(monkeypatch, tmp_path):
    monkeypatch.setattr("forensics.neo4j_client.Neo4jClient", _FakeNeo4jClient)
    gc = rb._graph_counts(_mini_plan(tmp_path), log=lambda _m: None)
    assert gc["status"] == "ok"
    assert gc["health"] == 42
    assert gc["counts"]["H1"] == {"events": 42, "processes": 42}
    assert gc["skipped"] == []


def test_graph_counts_partial_on_health_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "forensics.neo4j_client.Neo4jClient",
        lambda *a, **k: _FakeNeo4jClient(timeout_on="SPAWNED"),
    )
    gc = rb._graph_counts(_mini_plan(tmp_path), log=lambda _m: None)
    assert gc["status"] == "partial"
    assert gc["health"] is None  # health metric timed out
    assert "health:timeout" in gc["skipped"]
    # per-host counts still gathered
    assert gc["counts"]["H1"]["events"] == 42


# --- rebuild_case ALWAYS writes the summary, even if verify fails -----------


def _stub_pipeline(monkeypatch):
    monkeypatch.setattr(rb, "_run_wipe", lambda *a, **k: None)
    monkeypatch.setattr(rb, "_ensure_schema_once", lambda *a, **k: None)
    monkeypatch.setattr(
        rb,
        "_ingest_all",
        lambda plan, env, log: [{"hostname": "H1", "status": "ok", "attempts": 1, "dedup": []}],
    )
    monkeypatch.setattr(
        rb,
        "_run_hunts",
        lambda plan, env, log: [{"hunt": "event_coverage", "status": "pass", "rows": 3}],
    )


def _run_rebuild(monkeypatch, tmp_path):
    plan = _mini_plan(tmp_path)
    monkeypatch.setattr(rb, "build_plan", lambda *a, **k: plan)
    _stub_pipeline(monkeypatch)
    summary = rb.rebuild_case(
        CaseManifest.from_yaml(_CASE, project_root=_ROOT),
        tier="execution",
        workers=1,
        hunt_timeout=10,
        ingest_retries=0,
        database="neo4j",
        hunts_override=["event_coverage"],
        project_root=_ROOT,
        base_env={},
        log_path=tmp_path / "r.log",
        log=lambda _m: None,
    )
    return plan, summary


@_REQUIRES_CASE
def test_summary_written_even_when_verify_raises(monkeypatch, tmp_path):
    def boom(plan, log):
        raise RuntimeError("verify exploded")

    monkeypatch.setattr(rb, "_graph_counts", boom)
    plan, summary = _run_rebuild(monkeypatch, tmp_path)

    # the summary file MUST exist despite the verify explosion
    assert plan.summary_path.exists()
    written = json.loads(plan.summary_path.read_text())
    assert written["verify"]["status"] == "failed"
    assert "verify exploded" in written["verify"]["error"]
    # ingest + hunt results are preserved in the written summary
    assert written["host_status_counts"] == {"ok": 1}
    assert written["hunt_status_counts"]["pass"] == 1


@_REQUIRES_CASE
def test_summary_marks_verify_partial_on_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(
        rb,
        "_graph_counts",
        lambda plan, log: {
            "counts": {"H1": {"events": 100, "processes": 5}},
            "health": None,
            "status": "partial",
            "skipped": ["health:timeout"],
        },
    )
    plan, summary = _run_rebuild(monkeypatch, tmp_path)
    assert plan.summary_path.exists()
    assert summary["verify"]["status"] == "partial"
    assert summary["health"]["ok"] is False  # health was None
