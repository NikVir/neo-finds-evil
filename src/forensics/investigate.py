"""Run playbook hunt steps and write L3 investigation artifacts."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from forensics.case import CaseManifest
from forensics.case_paths import graphs_dir, steps_dir
from forensics.finding import record_finding
from forensics.graph_export import write_graph_doc
from forensics.hunt import run_hunt
from forensics.neo4j_case import client_for_case
from forensics.neo4j_client import Neo4jClient
from forensics.hunt_deps import artifacts_loaded, check_hunt_deps
from forensics.ingest.tiers import playbook_steps_for_tier, triage_playbook_steps
from forensics.manifest import HostManifest
from forensics.investigation_index import close_step, open_step, render_index_md
from forensics.playbooks import PlaybookStep, load_playbook


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _case_loaded_artifacts(case: CaseManifest, client: Neo4jClient) -> set[str]:
    loaded: set[str] = set()
    for host_path in case.hosts:
        hm = HostManifest.from_yaml(host_path)
        loaded |= artifacts_loaded(client, hm.hostname)
    return loaded


def run_playbook_step(
    case: CaseManifest,
    step: PlaybookStep,
    *,
    investigation_step_id: str,
    client: Neo4jClient,
) -> dict[str, Any]:
    """Execute one playbook step; return payload for response.json."""
    if step.status == "blocked_missing_artifact":
        return {
            "playbook_step": step.id,
            "status": "blocked",
            "reason": step.blocked_reason,
            "hypothesis_ref": step.hypothesis_ref,
        }
    if not step.hunt:
        return {"playbook_step": step.id, "status": "skipped", "reason": "no hunt defined"}

    loaded = _case_loaded_artifacts(case, client)
    dep = check_hunt_deps(step.hunt, loaded)
    if not dep.satisfied:
        return {
            "playbook_step": step.id,
            "status": "blocked",
            "reason": (
                f"Missing graph data for hunt {step.hunt}: "
                f"required={list(dep.missing_required)} any_of={list(dep.missing_any_of)}"
            ),
            "missing_artifacts": list(dep.missing_required) + list(dep.missing_any_of),
            "suggested_tier": dep.suggested_tier,
            "load_command": dep.load_command,
            "hypothesis_ref": step.hypothesis_ref,
        }

    result = run_hunt(step.hunt, client=client, case=case)
    return {
        "playbook_step": step.id,
        "hypothesis_ref": step.hypothesis_ref,
        "human_label": step.human_label,
        "expected_signals": step.expected_signals,
        "hunt": result,
    }


def _high_confidence_hits(hunt: dict[str, Any]) -> int | None:
    """Number of high-confidence rows a hunt is signalling.

    A hunt signals high-confidence detections in one of two ways:
      1. Explicitly, by putting an integer ``hit_count`` in its result dict.
      2. Implicitly, by returning a per-row ``confidence`` column; we count the
         rows whose confidence == 'high'.
    Returns None when the hunt provides neither signal (i.e. no ``hit_count`` and
    no row carries a ``confidence`` key) — so confidence-unaware hunts fall back
    to the legacy rows-based verdict unchanged.
    """
    explicit = hunt.get("hit_count")
    if explicit is not None:
        return int(explicit)
    rows = hunt.get("rows") or []
    if not any(isinstance(r, dict) and "confidence" in r for r in rows):
        return None
    return sum(1 for r in rows if isinstance(r, dict) and r.get("confidence") == "high")


def _verdict_from_payload(payload: dict[str, Any]) -> tuple[str, str]:
    if payload.get("status") == "blocked":
        return "not_assessed", "low"
    hunt = payload.get("hunt") or {}
    rows = hunt.get("rows") or []
    hits = _high_confidence_hits(hunt)
    if hits is not None and hits > 0:
        return "supported", "high"
    if len(rows) > 0:
        return "inconclusive", "medium"
    return "inconclusive", "low"


def run_playbook(
    case: CaseManifest,
    playbook_id: str | None = None,
    *,
    only_steps: set[str] | None = None,
    triage_only: bool = False,
    tier: str | None = None,
    write_investigation: bool = True,
    export_graphs: bool = True,
) -> list[dict[str, Any]]:
    pb = load_playbook(playbook_id or case.playbook)
    client = client_for_case(case)
    results: list[dict[str, Any]] = []
    triage_steps = set(triage_playbook_steps(case.case_type)) if triage_only else None
    tier_steps = set(playbook_steps_for_tier(case.case_type, tier)) if tier else None
    try:
        for i, step in enumerate(pb.steps):
            if only_steps and step.id not in only_steps:
                continue
            if triage_steps is not None and step.id not in triage_steps:
                continue
            if tier_steps is not None and step.id not in tier_steps:
                continue
            inv_id = f"{i + 2:03d}_{step.id.lower().replace('-', '_')}"
            payload = run_playbook_step(case, step, investigation_step_id=inv_id, client=client)
            results.append(payload)
            if write_investigation:
                _write_step_via_cm(
                    case, step, inv_id, payload, client=client, export_graphs=export_graphs
                )
            if step.hypothesis_ref and payload.get("status") != "blocked":
                verdict, confidence = _verdict_from_payload(payload)
                record_finding(
                    case_id=case.case_id,
                    hypothesis_id=step.hypothesis_ref,
                    verdict=verdict,
                    confidence=confidence,
                    step_id=inv_id,
                    summary=f"{step.id}: {step.human_label}",
                    client=client,
                )
    finally:
        client.close()
    return results


def _case_investigation_paths(case: CaseManifest, root: Path) -> tuple[Path, Path]:
    override = case.investigation_dir_override or None
    gdir = graphs_dir(case.case_id, root, override=override)
    sdir_root = steps_dir(case.case_id, root, override=override)
    return gdir, sdir_root


def _export_graph_for_step(
    case: CaseManifest, step: PlaybookStep, inv_id: str, *, client: Neo4jClient
) -> None:
    if not step.hunt:
        return
    root = _project_root()
    gdir, _ = _case_investigation_paths(case, root)
    gdir.mkdir(parents=True, exist_ok=True)
    safe_name = step.hunt.replace("_", "-")
    out = gdir / f"playbook_{inv_id}_{safe_name}.md"
    write_graph_doc(
        step.hunt,
        out,
        step_link=f"../steps/{inv_id}/review.md",
        hypothesis=step.hypothesis_ref or "",
        case=case,
        client=client,
    )


def _write_step_via_cm(
    case: CaseManifest,
    step: PlaybookStep,
    inv_id: str,
    payload: dict[str, Any],
    *,
    client: Neo4jClient,
    export_graphs: bool = True,
) -> None:
    root = _project_root()
    if export_graphs and step.hunt:
        try:
            _export_graph_for_step(case, step, inv_id, client=client)
        except Exception:
            pass

    cm = root / ".cursor" / "bin" / "cm"
    use_cm = cm.exists() and os.environ.get("FORENSICS_USE_CM", "1") != "0"
    _, sdir_root = _case_investigation_paths(case, root)
    sdir = sdir_root / inv_id

    if not use_cm:
        _write_step_with_index(root, case, step, inv_id, payload)
        return

    hyp = step.hypothesis_ref or step.human_label
    subprocess.run(
        [
            str(cm),
            "investigation",
            "open-step",
            "--id",
            inv_id,
            "--hypothesis",
            hyp,
            "--expected-outcome",
            step.expected_signals,
            "--case-id",
            case.case_id,
        ],
        cwd=root,
        check=False,
    )
    sdir.mkdir(parents=True, exist_ok=True)
    (sdir / "response.json").write_text(json.dumps(payload, indent=2, default=str))
    if step.hunt:
        from forensics.hunt import QUERIES

        if step.hunt in QUERIES:
            (sdir / "query.cypher").write_text(
                f"// playbook {step.id} hunt: {step.hunt}\n" + QUERIES[step.hunt].strip() + "\n"
            )

    outcome = "inconclusive"
    if payload.get("status") == "blocked":
        outcome = "inconclusive"
    one_line = f"{step.id}: {step.human_label}"
    rows = (payload.get("hunt") or {}).get("rows") or []
    if rows:
        one_line += f" ({len(rows)} rows)"

    subprocess.run(
        [
            str(cm),
            "investigation",
            "close-step",
            "--id",
            inv_id,
            "--case-id",
            case.case_id,
            "--outcome",
            outcome,
            "--one-line",
            one_line,
            "--queries",
            step.hunt or "",
        ],
        cwd=root,
        check=False,
    )
    subprocess.run(
        [str(cm), "investigation", "render-index", "--case-id", case.case_id],
        cwd=root,
        check=False,
    )


def _write_step_with_index(
    root: Path,
    case: CaseManifest,
    step: PlaybookStep,
    inv_id: str,
    payload: dict[str, Any],
) -> None:
    hyp = step.hypothesis_ref or step.human_label
    open_step(
        inv_id,
        case_id=case.case_id,
        hypothesis=hyp,
        expected_outcome=step.expected_signals,
        root=root,
    )
    _, sdir_root = _case_investigation_paths(case, root)
    sdir = sdir_root / inv_id
    (sdir / "response.json").write_text(json.dumps(payload, indent=2, default=str))
    if step.hunt:
        from forensics.hunt import QUERIES

        if step.hunt in QUERIES:
            (sdir / "query.cypher").write_text(
                f"// playbook {step.id} hunt: {step.hunt}\n" + QUERIES[step.hunt].strip() + "\n"
            )

    outcome = "inconclusive"
    one_line = f"{step.id}: {step.human_label}"
    rows = (payload.get("hunt") or {}).get("rows") or []
    if rows:
        one_line += f" ({len(rows)} rows)"
    close_step(
        inv_id,
        case_id=case.case_id,
        outcome=outcome,
        one_line=one_line,
        queries=[step.hunt] if step.hunt else None,
        root=root,
    )
    render_index_md(case.case_id, root=root)
