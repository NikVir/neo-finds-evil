"""CLI entry point for forensics ingest."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path

import click

from forensics.case import CaseManifest
from forensics.case_init import init_case_from_manifest
from forensics.case_paths import graphs_dir
from forensics.coverage import gather_coverage_metrics
from forensics.finding import record_finding
from forensics.hunt import QUERIES, run_hunt
from forensics.hunt_deps import build_ingest_plan
from forensics.ingest.runner import run_ingest
from forensics.ingest.tiers import DEFAULT_TIER, TIER_ORDER
from forensics.rebuild import (
    DEFAULT_HUNT_TIMEOUT,
    DEFAULT_INGEST_RETRIES,
    build_plan,
    default_workers,
    format_plan,
    rebuild_case,
    resolve_database,
)
from forensics.investigate import run_playbook
from forensics.manifest import HostManifest, discover_hosts
from forensics.neo4j_case import client_for_case
from forensics.neo4j_client import Neo4jClient
from forensics.path_discover import run_path_discover
from forensics.plaso_probe import probe_plaso
from forensics.registry import case_coverage_notes
from forensics.tag_sensitive import tag_sensitive_files


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_case(case: Path) -> CaseManifest:
    return CaseManifest.from_yaml(case, project_root=case.resolve().parent.parent.parent)


def _ensure_case_db(case: CaseManifest) -> None:
    script = _project_root() / "scripts" / "ensure-case-database.sh"
    if script.exists():
        subprocess.run(
            ["bash", str(script), case.neo4j_database()],
            check=False,
        )


def _client_for_cmd(case: CaseManifest | None) -> Neo4jClient:
    if case:
        return client_for_case(case)
    return Neo4jClient()


@click.group()
def main() -> None:
    """Forensics graph ingest framework."""


@main.command("run")
@click.option("--manifest", "-m", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--case", "-c", type=click.Path(exists=True, path_type=Path), default=None)
@click.option(
    "--only",
    default=None,
    help="Comma-separated artifacts: pslist,dlllist,netscan,evtx,path_catalog,mft,media_exif,usb",
)
@click.option("--skip-correlation", is_flag=True, help="Skip post-ingest correlation passes")
@click.option(
    "--force-reload",
    is_flag=True,
    help="Re-ingest artifacts even if already present in the graph",
)
@click.option(
    "--tier",
    default=None,
    type=click.Choice(list(TIER_ORDER)),
    help=f"Progressive ingest tier (default: {DEFAULT_TIER})",
)
@click.option("--full", is_flag=True, help="Load all artifacts (legacy full ingest)")
def run_cmd(
    manifest: Path,
    case: Path | None,
    only: str | None,
    skip_correlation: bool,
    force_reload: bool,
    tier: str | None,
    full: bool,
) -> None:
    """Run ingest for one host manifest."""
    m = HostManifest.from_yaml(manifest)
    only_set = {s.strip() for s in only.split(",")} if only else None
    cm = _load_case(case) if case else None
    if cm:
        _ensure_case_db(cm)
        cm.sync_host_case_ids([m])
    client = _client_for_cmd(cm)
    try:
        report = run_ingest(
            m,
            client,
            only=only_set,
            case=cm,
            tier=tier,
            full=full,
            skip_correlation=skip_correlation,
            force_reload=force_reload,
        )
        out: dict = report.to_dict()
        if cm:
            tagged = tag_sensitive_files(cm, client)
            out["sensitive_files_tagged"] = tagged
            out["case_coverage"] = case_coverage_notes(cm.case_type, report)
            out["coverage_metrics"] = gather_coverage_metrics(cm, report, client)
            out["neo4j_database"] = cm.neo4j_database()
        click.echo(json.dumps(out, indent=2))
    finally:
        client.close()


@main.command("discover")
@click.option("--data-dir", type=click.Path(exists=True, path_type=Path), required=True)
def discover_cmd(data_dir: Path) -> None:
    """List hostnames discoverable from *_pslist.json."""
    for h in discover_hosts(data_dir):
        click.echo(h)


@main.group("path")
def path_group() -> None:
    """Path discovery against graph File nodes."""


@path_group.command("discover")
@click.option("--case", "-c", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--min-score", default=0.4, type=float)
@click.option("--limit", default=200, type=int)
def path_discover_cmd(case: Path, min_score: float, limit: int) -> None:
    """Score and rank File paths using case discovery rules."""
    cm = _load_case(case)
    client = client_for_case(cm)
    try:
        result = run_path_discover(cm, min_score=min_score, limit=limit, client=client)
        click.echo(json.dumps(result, indent=2, default=str))
    finally:
        client.close()


@main.group("plaso")
def plaso_group() -> None:
    """Plaso store utilities."""


@plaso_group.command("probe")
@click.option("--store", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--data-type", default="fs:stat")
@click.option("--limit", default=5, type=int)
def plaso_probe_cmd(store: Path, data_type: str, limit: int) -> None:
    """Sample psort lines and list field keys for a data type."""
    result = probe_plaso(store, data_type=data_type, limit=limit)
    click.echo(json.dumps(result, indent=2, default=str))


@main.command("hunt")
@click.argument("query", default="summary")
@click.option("--case", "-c", type=click.Path(exists=True, path_type=Path), default=None)
def hunt_cmd(query: str, case: Path | None) -> None:
    """Run built-in DFIR hunt query against Neo4j."""
    available = sorted(set(QUERIES) | {"path_discover"})
    if query not in available:
        raise click.ClickException(f"Unknown query. Choose from: {', '.join(available)}")
    cm = _load_case(case) if case else None
    if query in ("path_discover",) and not cm:
        raise click.ClickException("--case required for path_discover")
    client = _client_for_cmd(cm)
    try:
        result = run_hunt(query, client=client, case=cm)
        click.echo(json.dumps(result, indent=2, default=str))
    finally:
        client.close()


@main.group("finding")
def finding_group() -> None:
    """Record investigation findings in Neo4j."""


@finding_group.command("record")
@click.option("--case-id", required=True)
@click.option("--hypothesis", required=True)
@click.option("--verdict", required=True)
@click.option("--confidence", default="medium")
@click.option("--step-id", required=True)
@click.option("--summary", default="")
@click.option("--case-config", "-c", type=click.Path(exists=True, path_type=Path), default=None)
def finding_record_cmd(
    case_id: str,
    hypothesis: str,
    verdict: str,
    confidence: str,
    step_id: str,
    summary: str,
    case_config: Path | None,
) -> None:
    """MERGE a Finding node for a playbook step."""
    cm = _load_case(case_config) if case_config else None
    client = _client_for_cmd(cm)
    try:
        result = record_finding(
            case_id=case_id,
            hypothesis_id=hypothesis,
            verdict=verdict,
            confidence=confidence,
            step_id=step_id,
            summary=summary,
            client=client,
        )
        click.echo(json.dumps(result, indent=2))
    finally:
        client.close()


@main.group("investigate")
def investigate_group() -> None:
    """Case playbook investigation steps."""


@investigate_group.command("run-playbook")
@click.option("--case", "-c", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--playbook", default=None, help="Override case playbook id")
@click.option("--only", default=None, help="Comma-separated playbook step ids")
@click.option("--no-write", is_flag=True, help="Do not write investigation/ steps")
@click.option("--no-export-graphs", is_flag=True, help="Skip investigation/graphs per hunt")
@click.option(
    "--triage-only",
    is_flag=True,
    help="Run only triage playbook steps (default for run-phase2-case.sh)",
)
@click.option(
    "--tier",
    default=None,
    help="Run cumulative playbook steps for a tier (e.g. execution = triage + execution steps)",
)
def run_playbook_cmd(
    case: Path,
    playbook: str | None,
    only: str | None,
    no_write: bool,
    no_export_graphs: bool,
    triage_only: bool,
    tier: str | None,
) -> None:
    """Run case playbook hunts and write L3 investigation artifacts."""
    cm = _load_case(case)
    _ensure_case_db(cm)
    only_set = {s.strip() for s in only.split(",")} if only else None
    results = run_playbook(
        cm,
        playbook,
        only_steps=only_set,
        triage_only=triage_only,
        tier=tier,
        write_investigation=not no_write,
        export_graphs=not no_export_graphs,
    )
    click.echo(json.dumps(results, indent=2, default=str))


@investigate_group.command("list-playbook")
@click.option("--case", "-c", type=click.Path(exists=True, path_type=Path), required=True)
def list_playbook_cmd(case: Path) -> None:
    """List playbook steps for a case."""
    from forensics.playbooks import load_playbook

    cm = _load_case(case)
    pb = load_playbook(cm.playbook)
    for s in pb.steps:
        click.echo(f"{s.id}\t{s.status}\t{s.hunt or '-'}\t{s.human_label}")


@main.group("graph")
def graph_group() -> None:
    """Export graph views as Markdown (Cypher + Mermaid)."""


@graph_group.command("export")
@click.argument("hunt")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None)
@click.option("--step", default="", help="Investigation step id for header link")
@click.option("--hypothesis", default="", help="Hypothesis label in header")
@click.option("--case", "-c", type=click.Path(exists=True, path_type=Path), default=None)
def graph_export_cmd(
    hunt: str,
    output: Path | None,
    step: str,
    hypothesis: str,
    case: Path | None,
) -> None:
    """Run hunt and write investigation/<case_id>/graphs/*.md with diagram."""
    from forensics.graph_export import write_graph_doc

    available = sorted(set(QUERIES) | {"path_discover"})
    if hunt not in available:
        raise click.ClickException(f"Unknown hunt. Choose from: {', '.join(available)}")
    cm = _load_case(case) if case else None
    if output is None:
        if not cm:
            raise click.ClickException("-o or --case required for graph export")
        root = _project_root()
        override = cm.investigation_dir_override or None
        out_dir = graphs_dir(cm.case_id, root, override=override)
        out_dir.mkdir(parents=True, exist_ok=True)
        output = out_dir / f"{hunt}.md"
    step_link = f"../steps/{step}/review.md" if step else ""
    client = _client_for_cmd(cm)
    try:
        path = write_graph_doc(
            hunt,
            output,
            step_link=step_link,
            hypothesis=hypothesis,
            case=cm,
            client=client,
        )
        click.echo(path)
    finally:
        client.close()


@main.command("init-case")
@click.option("--case", "-c", type=click.Path(exists=True, path_type=Path), required=True)
def init_case_cmd(case: Path) -> None:
    """Scaffold investigation/<case_id>/ from case YAML."""
    cm = _load_case(case)
    cdir = init_case_from_manifest(cm)
    click.echo(cdir)


@main.command("plan")
@click.option("--case", "-c", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--hunt", default=None, help="Check graph readiness for a specific hunt")
def plan_cmd(case: Path, hunt: str | None) -> None:
    """Show loaded vs available artifacts per host; optional hunt dependency check."""
    cm = _load_case(case)
    client = client_for_case(cm)
    try:
        hostnames = [HostManifest.from_yaml(h).hostname for h in cm.hosts]
        result = build_ingest_plan(cm.case_type, hostnames, client, hunt=hunt)
        click.echo(json.dumps(result, indent=2))
    finally:
        client.close()


@main.command("load-tier")
@click.argument("tier", type=click.Choice(list(TIER_ORDER)))
@click.option("--manifest", "-m", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--case", "-c", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--skip-correlation", is_flag=True, help="Skip post-ingest correlation passes")
@click.option(
    "--force-reload",
    is_flag=True,
    help="Re-ingest artifacts even if already present in the graph",
)
def load_tier_cmd(
    tier: str,
    manifest: Path,
    case: Path | None,
    skip_correlation: bool,
    force_reload: bool,
) -> None:
    """Load an ingest tier for one host (alias for run --tier)."""
    m = HostManifest.from_yaml(manifest)
    cm = _load_case(case) if case else None
    if cm:
        _ensure_case_db(cm)
        cm.sync_host_case_ids([m])
    client = _client_for_cmd(cm)
    try:
        report = run_ingest(
            m,
            client,
            case=cm,
            tier=tier,
            skip_correlation=skip_correlation,
            force_reload=force_reload,
        )
        click.echo(json.dumps(report.to_dict(), indent=2))
    finally:
        client.close()


def _make_logger(stream, echo: bool):
    def log(msg: str) -> None:
        line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
        stream.write(line + "\n")
        stream.flush()
        if echo:
            click.echo(line)

    return log


def _execute_rebuild(cm, root, log_path, *, echo, **kwargs) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as lf:
        log = _make_logger(lf, echo=echo)
        try:
            summary = rebuild_case(
                cm,
                project_root=root,
                base_env=dict(os.environ),
                log_path=log_path,
                log=log,
                **kwargs,
            )
        except Exception as exc:  # noqa: BLE001 - log and fail cleanly
            log(f"REBUILD FAILED: {exc}")
            return 1
        # Exit code reflects the core work (ingest), not reporting hiccups: a
        # partial/failed VERIFY or a 0 health metric is surfaced in the summary
        # but must not, on its own, fail an otherwise-good rebuild.
        return 1 if summary["host_status_counts"].get("failed") else 0


@main.command("rebuild-case")
@click.option("--case", "-c", type=click.Path(exists=True, path_type=Path), required=True)
@click.option(
    "--tier",
    default="execution",
    type=click.Choice(list(TIER_ORDER)),
    help="Ingest tier for every host (default: execution)",
)
@click.option(
    "--workers", default=None, type=int, help="Parallel ingest workers (default: ~nproc/2)"
)
@click.option(
    "--hunt-timeout", default=DEFAULT_HUNT_TIMEOUT, type=int, help="Per-hunt timeout in seconds"
)
@click.option(
    "--ingest-retries",
    default=DEFAULT_INGEST_RETRIES,
    type=int,
    help="Extra attempts per host on failure",
)
@click.option(
    "--database", default=None, help="Override Neo4j database (default: neo4j / Community)"
)
@click.option(
    "--hunts", default=None, help="Comma-separated hunt override (default: case playbook)"
)
@click.option("--dry-run", is_flag=True, help="Print the full plan and exit without executing")
@click.option(
    "--detach", is_flag=True, help="Fork to background, logging to a file; return at once"
)
def rebuild_case_cmd(
    case: Path,
    tier: str,
    workers: int | None,
    hunt_timeout: int,
    ingest_retries: int,
    database: str | None,
    hunts: str | None,
    dry_run: bool,
    detach: bool,
) -> None:
    """Wipe + parallel-ingest all hosts + run hunts + verify, in one command."""
    cm = _load_case(case)
    root = _project_root()
    resolved_workers = workers if workers else default_workers(os.cpu_count() or 2)
    resolved_db = resolve_database(os.environ.get("NEO4J_DATABASE"), database)
    hunts_override = [s.strip() for s in hunts.split(",") if s.strip()] if hunts else None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = cm.investigation_path(root) / f"rebuild-{stamp}.log"

    if dry_run:
        plan = build_plan(
            cm,
            tier=tier,
            workers=resolved_workers,
            hunt_timeout=hunt_timeout,
            ingest_retries=ingest_retries,
            database=resolved_db,
            hunts_override=hunts_override,
            log_path=log_path,
            project_root=root,
        )
        click.echo(format_plan(plan))
        return

    run_kwargs = dict(
        tier=tier,
        workers=resolved_workers,
        hunt_timeout=hunt_timeout,
        ingest_retries=ingest_retries,
        database=resolved_db,
        hunts_override=hunts_override,
    )

    if detach and hasattr(os, "fork"):
        log_path.parent.mkdir(parents=True, exist_ok=True)
        pid = os.fork()
        if pid > 0:
            click.echo(f"rebuild-case running detached (pid {pid}).")
            click.echo(f"  tail -f {log_path}")
            return
        # Child: new session, stdout/stderr -> logfile, run to completion.
        os.setsid()
        fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        os.close(fd)
        rc = _execute_rebuild(cm, root, log_path, echo=False, **run_kwargs)
        os._exit(rc)

    click.echo(f"rebuild-case: logging to {log_path}")
    rc = _execute_rebuild(cm, root, log_path, echo=True, **run_kwargs)
    if rc != 0:
        raise click.ClickException("rebuild-case completed with failures (see log/summary)")


if __name__ == "__main__":
    main()
