"""Reproducible single-command case rebuild orchestration.

``forensics-ingest rebuild-case -c config/cases/<case>.yaml``

Supersedes the hand-assembled ``wipe -> parallel-ingest -> hunts -> verify``
shell pipeline (and the older ``scripts/run-phase2-case.sh``) with one safe,
idempotent, re-runnable entry point. The non-obvious hazards this is designed
around — each learned the hard way running the pipeline by hand:

1. **Neo4j Community = single database.** The case YAML's ``neo4j.database`` and
   the case_id both suggest a per-case DB name, but Community only has the DB
   literally named ``neo4j``; pointing a child at ``srl2018`` crashes with
   "Graph not found". Every child process is therefore forced to
   ``NEO4J_DATABASE=neo4j`` (see :func:`resolve_database`).
2. **Disk-only hosts.** ``pslist`` is force-required in the runner, so a host
   with no memory image raises ``FileNotFoundError`` and kills the run. We set
   ``ALLOW_MISSING_PSLIST=1`` for every child (it only downgrades a *genuinely*
   missing pslist to a recorded skip; hosts that have pslist load normally).
3. **Reporting/stats queries that blow up at scale.** Stacked OPTIONAL MATCH /
   unanchored patterns Cartesian-multiply on a large graph and never return.
   Fixed at the source (the ``summary`` hunt and per-host stats are now
   per-relationship anchored counts), and every hunt is timeout-guarded; the
   ``EXCLUDED_HUNTS`` set remains as a quarantine for any future known-bad hunt.
4. **Parallel worker count.** The per-host Python feeder is single-threaded, so
   parallelism *across* hosts is the win; Neo4j has headroom. Default is
   conservative relative to nproc (see :func:`default_workers`) to leave room
   for Neo4j; configurable.
5. **Schema race.** The schema is ensured ONCE up front; children are told to
   skip it (``FORENSICS_SCHEMA_READY=1``) so N parallel ``CREATE CONSTRAINT``
   storms can't throw transient errors.
6. **Concurrent-MERGE deadlocks** on shared nodes (IPAddress, RegistryKey) are
   absorbed by retry-with-backoff in the Neo4j client.

The command is also detach-able (the CLI can fork it to a logfile) so a long
rebuild doesn't wedge an interactive shell.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from forensics.case import CaseManifest
from forensics.manifest import HostManifest
from forensics.playbooks import load_playbook

# Hunts excluded from a rebuild. Empty since the `summary` hunt was rewritten to
# per-host CALL subqueries (no Cartesian blow-up; <1s for 7 hosts) and re-included.
# The per-hunt subprocess timeout in _run_hunts is the safety net for any hunt
# that misbehaves at scale, so nothing needs to be hard-excluded today; this
# constant remains the place to quarantine a future known-bad hunt.
EXCLUDED_HUNTS: frozenset[str] = frozenset()

_DEFAULT_WORKER_CAP = 4
DEFAULT_HUNT_TIMEOUT = 150
DEFAULT_INGEST_RETRIES = 1

# Health/payoff metric: 0 before the Sysmon projection fix (commit 6b0a0dd),
# non-zero once EID-1 -> SPAWNED edges are built. A quick "did it work" check.
HEALTH_METRIC_CYPHER = "MATCH ()-[r:SPAWNED {source: 'sysmon'}]->() RETURN count(r) AS c"


# --------------------------------------------------------------------------- #
# Pure planning helpers (unit-tested without touching Neo4j or the filesystem)
# --------------------------------------------------------------------------- #


def default_workers(nproc: int, cap: int = _DEFAULT_WORKER_CAP) -> int:
    """Parallel ingest workers: ~half the cores, capped, never below 1.

    The per-host feeder is single-threaded and Neo4j needs headroom, so we
    deliberately do NOT use all cores. On the 8-core reference box this yields
    4, the observed sweet spot.
    """
    return max(1, min(cap, nproc // 2))


def resolve_database(env_database: str | None, requested: str | None = None) -> str:
    """Resolve the Neo4j database for all children.

    Defaults to ``neo4j`` — the only database that exists on Community Edition.
    An explicit CLI ``--database`` or ``NEO4J_DATABASE`` env wins (for an
    Enterprise multi-DB deployment), but the safe single-DB default is ``neo4j``.
    """
    return (requested or env_database or "neo4j").strip() or "neo4j"


def select_hunts(
    playbook_hunts: list[str],
    available: set[str] | frozenset[str],
    exclude: set[str] | frozenset[str] = EXCLUDED_HUNTS,
    override: list[str] | None = None,
) -> list[str]:
    """Order-preserving, de-duplicated hunt selection.

    Source of truth is the case playbook's hunts (so the list tracks the
    playbook and can't rot), intersected with the hunts that actually exist,
    minus the always-excluded set. ``override`` (CLI ``--hunts``) replaces the
    playbook source but is still filtered to existing hunts.
    """
    source = override if override is not None else playbook_hunts
    seen: set[str] = set()
    out: list[str] = []
    for h in source:
        if h in available and h not in exclude and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def classify_hunt_result(returncode: int | None, timed_out: bool, rows: int | None) -> str:
    """Map a hunt run to pass / empty / fail / timeout."""
    if timed_out:
        return "timeout"
    if returncode != 0 or rows is None:
        return "fail"
    return "pass" if rows > 0 else "empty"


def rows_in_output(parsed: dict | None) -> int | None:
    """Row count from a hunt's JSON output, or None if it errored/unparseable."""
    if not isinstance(parsed, dict) or "error" in parsed:
        return None
    rows = parsed.get("rows")
    return len(rows) if isinstance(rows, list) else None


@dataclass(frozen=True)
class HostPlan:
    hostname: str
    manifest_path: Path
    spill_cache: Path
    pslist_present: bool  # best-effort; False => treated as disk-only host


@dataclass(frozen=True)
class RebuildPlan:
    case_id: str
    case_config: Path
    database: str
    tier: str
    workers: int
    hunt_timeout: int
    ingest_retries: int
    hosts: list[HostPlan]
    hunts: list[str]
    wipe_caches: list[str]
    investigation_dir: Path
    hunts_dir: Path
    log_path: Path
    summary_path: Path
    allow_missing_pslist: bool = True

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "case_config": str(self.case_config),
            "neo4j_database": self.database,
            "tier": self.tier,
            "workers": self.workers,
            "hunt_timeout_s": self.hunt_timeout,
            "ingest_retries": self.ingest_retries,
            "allow_missing_pslist": self.allow_missing_pslist,
            "hosts": [
                {
                    "hostname": h.hostname,
                    "manifest": str(h.manifest_path),
                    "memory": h.pslist_present,
                }
                for h in self.hosts
            ],
            "wipe": {
                "database": self.database,
                "ingest_caches": self.wipe_caches,
            },
            "hunts": self.hunts,
            "excluded_hunts": sorted(EXCLUDED_HUNTS),
            "outputs": {
                "hunts_dir": str(self.hunts_dir),
                "log": str(self.log_path),
                "summary": str(self.summary_path),
            },
        }


def ingest_command(plan: RebuildPlan, host: HostPlan) -> list[str]:
    """argv for one host's ingest child (runs the same interpreter, no uv)."""
    return [
        sys.executable,
        "-m",
        "forensics.cli",
        "run",
        "-m",
        str(host.manifest_path),
        "-c",
        str(plan.case_config),
        "--tier",
        plan.tier,
    ]


def hunt_command(plan: RebuildPlan, hunt: str) -> list[str]:
    """argv for one hunt child."""
    return [
        sys.executable,
        "-m",
        "forensics.cli",
        "hunt",
        hunt,
        "-c",
        str(plan.case_config),
    ]


def aggregate_summary(
    plan: RebuildPlan,
    host_results: list[dict],
    hunt_results: list[dict],
    graph_counts: dict,
    health: int | None,
) -> dict:
    """Build the final verification summary (pure; takes already-gathered data).

    Aggregates: per-host ingest status + event/process counts, the dedup
    collapse (kept/dropped/unique per class, summed and per-host), and each
    hunt's pass/empty/fail/timeout with row counts.
    """
    dedup_total_dropped = 0
    dedup_by_class: dict[int, dict] = {}
    hosts_out: list[dict] = []
    for hr in host_results:
        host = hr.get("hostname", "?")
        counts = graph_counts.get(host, {})
        dedup = hr.get("dedup") or []
        for entry in dedup:
            eid = entry.get("event_id")
            dropped = int(entry.get("dropped", 0) or 0)
            dedup_total_dropped += dropped
            agg = dedup_by_class.setdefault(
                eid,
                {"event_id": eid, "label": entry.get("label", ""), "kept": 0, "dropped": 0},
            )
            agg["kept"] += int(entry.get("kept", 0) or 0)
            agg["dropped"] += dropped
        hosts_out.append(
            {
                "hostname": host,
                "status": hr.get("status", "unknown"),
                "events": counts.get("events"),
                "processes": counts.get("processes"),
                "attempts": hr.get("attempts", 1),
                "dedup": dedup,
                "error": hr.get("error"),
            }
        )

    hunt_tally = {"pass": 0, "empty": 0, "fail": 0, "timeout": 0}
    for hres in hunt_results:
        hunt_tally[hres.get("status", "fail")] = hunt_tally.get(hres.get("status", "fail"), 0) + 1

    return {
        "case_id": plan.case_id,
        "neo4j_database": plan.database,
        "tier": plan.tier,
        "hosts": hosts_out,
        "host_status_counts": _tally([h["status"] for h in hosts_out]),
        "dedup": {
            "total_dropped": dedup_total_dropped,
            "by_class": sorted(dedup_by_class.values(), key=lambda d: str(d["event_id"])),
        },
        "hunts": hunt_results,
        "hunt_status_counts": hunt_tally,
        "health": {
            "sysmon_spawned_edges": health,
            "ok": bool(health and health > 0),
        },
    }


def _tally(values: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


# --------------------------------------------------------------------------- #
# Plan construction (reads case/host YAML — deterministic, no graph access)
# --------------------------------------------------------------------------- #


def _pslist_present(manifest: HostManifest) -> bool:
    """Best-effort: does this host have a pslist artifact on disk?

    Read-only existence check (the loader reads the same file). A host with no
    memory image has no pslist JSON -> treated as disk-only.
    """
    try:
        return manifest.artifact_path("pslist").exists()
    except (KeyError, OSError, ValueError):
        return False


def build_plan(
    case: CaseManifest,
    *,
    tier: str,
    workers: int,
    hunt_timeout: int,
    ingest_retries: int,
    database: str,
    hunts_override: list[str] | None,
    log_path: Path,
    project_root: Path,
) -> RebuildPlan:
    manifests = [(p, HostManifest.from_yaml(p)) for p in case.hosts]
    hosts = [
        HostPlan(
            hostname=m.hostname,
            manifest_path=p,
            spill_cache=(m.spill_dir or (m.data_dir / ".ingest_cache")),
            pslist_present=_pslist_present(m),
        )
        for p, m in manifests
    ]

    playbook_hunts: list[str] = []
    try:
        pb = load_playbook(case.playbook)
        playbook_hunts = [s.hunt for s in pb.steps if s.hunt]
    except FileNotFoundError:
        playbook_hunts = []

    from forensics.hunt import QUERIES

    hunts = select_hunts(playbook_hunts, set(QUERIES), override=hunts_override)

    inv_dir = case.investigation_path(project_root)
    hunts_dir = inv_dir / "hunts"
    summary_path = inv_dir / "rebuild-summary.json"

    return RebuildPlan(
        case_id=case.case_id,
        case_config=case.config_path or Path(""),
        database=database,
        tier=tier,
        workers=workers,
        hunt_timeout=hunt_timeout,
        ingest_retries=ingest_retries,
        hosts=hosts,
        hunts=hunts,
        wipe_caches=[str(h.spill_cache) for h in hosts],
        investigation_dir=inv_dir,
        hunts_dir=hunts_dir,
        log_path=log_path,
        summary_path=summary_path,
    )


def format_plan(plan: RebuildPlan) -> str:
    """Human-readable dry-run rendering of the full plan."""
    lines: list[str] = []
    lines.append(f"REBUILD PLAN — case {plan.case_id}")
    lines.append(f"  config         : {plan.case_config}")
    lines.append(f"  neo4j database : {plan.database}  (forced for all children)")
    lines.append(f"  ingest tier    : {plan.tier}")
    lines.append(f"  parallel workers: {plan.workers}")
    lines.append(f"  hunt timeout   : {plan.hunt_timeout}s   ingest retries: {plan.ingest_retries}")
    lines.append(f"  ALLOW_MISSING_PSLIST=1 for all children: {plan.allow_missing_pslist}")
    lines.append("")
    lines.append("WIPE (DETACH DELETE on db + clear spill caches):")
    for c in plan.wipe_caches:
        lines.append(f"  - {c}")
    lines.append("")
    lines.append(f"INGEST {len(plan.hosts)} host(s) in parallel:")
    for h in plan.hosts:
        mem = "memory+disk" if h.pslist_present else "disk-only (no pslist -> skip)"
        lines.append(f"  - {h.hostname:<14} [{mem}]  {h.manifest_path}")
    lines.append("")
    lines.append(f"HUNTS ({len(plan.hunts)}, excluding {sorted(EXCLUDED_HUNTS)}):")
    lines.append("  " + ", ".join(plan.hunts))
    lines.append("")
    lines.append("OUTPUTS:")
    lines.append(f"  hunts dir : {plan.hunts_dir}/<hunt>.json (+ .err)")
    lines.append(f"  summary   : {plan.summary_path}")
    lines.append(f"  log       : {plan.log_path}")
    lines.append("")
    lines.append("(dry run — nothing executed)")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Execution (impure). Each step logs via the provided callable.
# --------------------------------------------------------------------------- #

Logger = Callable[[str], None]


@dataclass
class _ChildEnv:
    """Environment forced onto every child process."""

    base: dict = field(default_factory=dict)

    def build(self, plan: RebuildPlan) -> dict:
        env = dict(self.base)
        env["NEO4J_DATABASE"] = plan.database  # caveat 1
        if plan.allow_missing_pslist:
            env["ALLOW_MISSING_PSLIST"] = "1"  # caveat 2
        env["FORENSICS_SCHEMA_READY"] = "1"  # caveat 5 (schema ensured once, up front)
        return env


def _run_wipe(plan: RebuildPlan, project_root: Path, env: dict, log: Logger) -> None:
    script = project_root / "scripts" / "wipe-neo4j-graph.sh"
    cmd = ["bash", str(script)]
    for cache in plan.wipe_caches:
        cmd += ["--ingest-cache", cache]
    log(f"WIPE: {' '.join(cmd)}")
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    log(proc.stdout.strip())
    if proc.returncode != 0:
        log(f"WIPE FAILED ({proc.returncode}): {proc.stderr.strip()}")
        raise RuntimeError(f"graph wipe failed: {proc.stderr.strip()}")


def _ensure_schema_once(plan: RebuildPlan, log: Logger) -> None:
    from forensics.neo4j_client import Neo4jClient

    log(f"SCHEMA: ensuring constraints/indexes once on db '{plan.database}'")
    client = Neo4jClient(database=plan.database)
    try:
        client.ensure_schema()
    finally:
        client.close()


def _ingest_host(plan: RebuildPlan, host: HostPlan, env: dict, log: Logger) -> dict:
    cmd = ingest_command(plan, host)
    attempts = max(1, plan.ingest_retries + 1)
    last_err = ""
    for attempt in range(1, attempts + 1):
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if proc.returncode == 0:
            report = _parse_last_json(proc.stdout)
            dedup = _dedup_from_report(report)
            log(f"  [{host.hostname}] OK (attempt {attempt})")
            return {
                "hostname": host.hostname,
                "status": "ok",
                "attempts": attempt,
                "dedup": dedup,
            }
        last_err = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:] or [""]
        last_err = last_err[0]
        log(f"  [{host.hostname}] FAILED attempt {attempt}/{attempts}: {last_err}")
    return {
        "hostname": host.hostname,
        "status": "failed",
        "attempts": attempts,
        "dedup": [],
        "error": last_err,
    }


def _ingest_all(plan: RebuildPlan, env: dict, log: Logger) -> list[dict]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    log(f"INGEST: {len(plan.hosts)} host(s), {plan.workers} parallel worker(s), tier={plan.tier}")
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=plan.workers) as pool:
        futures = {pool.submit(_ingest_host, plan, h, env, log): h for h in plan.hosts}
        for fut in as_completed(futures):
            results.append(fut.result())
    results.sort(key=lambda r: r["hostname"])
    ok = sum(1 for r in results if r["status"] == "ok")
    log(f"INGEST done: {ok}/{len(results)} hosts OK")
    return results


def _run_hunts(plan: RebuildPlan, env: dict, log: Logger) -> list[dict]:
    plan.hunts_dir.mkdir(parents=True, exist_ok=True)
    log(f"HUNTS: {len(plan.hunts)} hunt(s), {plan.hunt_timeout}s timeout each -> {plan.hunts_dir}")
    results: list[dict] = []
    for hunt in plan.hunts:
        out_path = plan.hunts_dir / f"{hunt}.json"
        err_path = plan.hunts_dir / f"{hunt}.err"
        cmd = hunt_command(plan, hunt)
        timed_out = False
        rc: int | None = None
        rows: int | None = None
        try:
            proc = subprocess.run(
                cmd, env=env, capture_output=True, text=True, timeout=plan.hunt_timeout
            )
            rc = proc.returncode
            out_path.write_text(proc.stdout)
            err_path.write_text(proc.stderr)
            rows = rows_in_output(_parse_last_json(proc.stdout))
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            partial = exc.stdout or ""
            out_path.write_text(
                partial if isinstance(partial, str) else partial.decode("utf-8", "replace")
            )
            err_path.write_text(f"TIMEOUT after {plan.hunt_timeout}s")
        status = classify_hunt_result(rc, timed_out, rows)
        log(f"  [{hunt}] {status}" + (f" ({rows} rows)" if rows is not None else ""))
        results.append({"hunt": hunt, "status": status, "rows": rows, "output": str(out_path)})
    return results


# Per-host, per-relationship-type anchored counts. The previous VERIFY query was
# one global `MATCH (h:Host) OPTIONAL MATCH (p)-[:RAN_ON]->(h) OPTIONAL MATCH
# (e)-[:REPORTED]->(h) ...` — the two stacked OPTIONAL MATCHes Cartesian-multiply
# processes x events per host across all 7 hosts and never returned (>8min,
# killed). These are single relationship scans anchored on one hostname.
_VERIFY_EVENTS_CYPHER = (
    "MATCH (h:Host {hostname: $h})<-[:REPORTED]-(e:WindowsEvent) RETURN count(e) AS c"
)
_VERIFY_PROCS_CYPHER = "MATCH (h:Host {hostname: $h})<-[:RAN_ON]-(p:Process) RETURN count(p) AS c"


def _graph_counts(plan: RebuildPlan, log: Logger) -> dict:
    """Per-host counts + health metric. NEVER raises; degrades to partial.

    Returns {counts, health, status: ok|partial, skipped: [...]}. Every query is
    guarded with a server-side timeout so a slow/broken stat is recorded as
    skipped (null value) instead of wedging the rebuild.
    """
    from forensics.neo4j_client import Neo4jClient, stats_query_timeout

    timeout = stats_query_timeout()
    counts: dict[str, dict] = {}
    skipped: list[str] = []
    health: int | None = None
    status = "ok"
    client = Neo4jClient(database=plan.database)
    try:
        for host in plan.hosts:
            params = {"h": host.hostname}
            ev_rows, ev_st = client.query_guarded(_VERIFY_EVENTS_CYPHER, params, timeout=timeout)
            pr_rows, pr_st = client.query_guarded(_VERIFY_PROCS_CYPHER, params, timeout=timeout)
            counts[host.hostname] = {
                "events": ev_rows[0]["c"] if ev_rows else None,
                "processes": pr_rows[0]["c"] if pr_rows else None,
            }
            for label, st in (("events", ev_st), ("processes", pr_st)):
                if st != "ok":
                    status = "partial"
                    skipped.append(f"{host.hostname}:{label}:{st}")
                    log(f"  VERIFY stat skipped: {host.hostname} {label} ({st})")
        hv_rows, hv_st = client.query_guarded(HEALTH_METRIC_CYPHER, timeout=timeout)
        if hv_rows:
            health = int(hv_rows[0]["c"])
        if hv_st != "ok":
            status = "partial"
            skipped.append(f"health:{hv_st}")
            log(f"  VERIFY stat skipped: health metric ({hv_st})")
    finally:
        client.close()
    return {"counts": counts, "health": health, "status": status, "skipped": skipped}


def _parse_last_json(text: str) -> dict | None:
    """Parse the last JSON object printed on stdout (children print one report).

    Robust to leading log noise: tries the whole string, then the last balanced
    object.
    """
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    while start != -1:
        try:
            return json.loads(text[start:])
        except json.JSONDecodeError:
            start = text.find("{", start + 1)
    return None


def _dedup_from_report(report: dict | None) -> list[dict]:
    if not isinstance(report, dict):
        return []
    for art in report.get("artifacts", []):
        if art.get("name") == "evtx" and art.get("dedup"):
            return art["dedup"]
    return []


def rebuild_case(
    case: CaseManifest,
    *,
    tier: str,
    workers: int,
    hunt_timeout: int,
    ingest_retries: int,
    database: str,
    hunts_override: list[str] | None,
    project_root: Path,
    base_env: dict,
    log_path: Path,
    log: Logger,
) -> dict:
    """Execute a full rebuild and return the verification summary dict.

    Order: wipe -> ensure schema once -> parallel ingest -> hunts -> verify.
    Idempotent: re-running wipes and rebuilds from the (full, on-disk) artifacts.
    """
    plan = build_plan(
        case,
        tier=tier,
        workers=workers,
        hunt_timeout=hunt_timeout,
        ingest_retries=ingest_retries,
        database=database,
        hunts_override=hunts_override,
        log_path=log_path,
        project_root=project_root,
    )
    env = _ChildEnv(base=base_env).build(plan)

    log(f"=== REBUILD case {plan.case_id} (db={plan.database}, tier={plan.tier}) ===")
    _run_wipe(plan, project_root, env, log)
    _ensure_schema_once(plan, log)
    host_results = _ingest_all(plan, env, log)
    hunt_results = _run_hunts(plan, env, log)

    log("VERIFY: gathering per-host counts + health metric")
    verify: dict = {"status": "ok", "skipped": []}
    counts: dict = {}
    health: int | None = None
    # _graph_counts is written not to raise, but VERIFY must never be able to
    # lose the summary — so it is also wrapped defensively. (2026-06-05: a hung
    # verify query killed the orchestrator and no rebuild-summary.json was
    # written even though ingest + all 17 hunts had succeeded.)
    try:
        gc = _graph_counts(plan, log)
        counts = gc["counts"]
        health = gc["health"]
        verify = {"status": gc["status"], "skipped": gc["skipped"]}
    except Exception as exc:  # noqa: BLE001 - degrade, never lose the summary
        verify = {"status": "failed", "error": str(exc), "skipped": []}
        log(f"VERIFY failed (continuing; summary still written): {exc}")

    summary = aggregate_summary(plan, host_results, hunt_results, counts, health)
    summary["verify"] = verify

    # The summary is ALWAYS written, even on partial/failed verify.
    try:
        plan.summary_path.write_text(json.dumps(summary, indent=2, default=str))
        log(f"SUMMARY written: {plan.summary_path}")
    except OSError as exc:
        log(f"WARNING: could not write summary file {plan.summary_path}: {exc}")

    log(
        "DONE: "
        f"hosts {summary['host_status_counts']}, "
        f"hunts {summary['hunt_status_counts']}, "
        f"verify {verify['status']}, "
        f"dedup dropped {summary['dedup']['total_dropped']}, "
        f"sysmon SPAWNED edges {health}"
    )
    return summary
