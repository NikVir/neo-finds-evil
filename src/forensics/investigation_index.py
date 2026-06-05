"""Investigation L2 INDEX.yaml + L3 step folders (framework-native, no Cursor memory)."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from forensics.case_paths import INVESTIGATION_DIR
from forensics.case_paths import investigation_l3_path

INDEX_YAML = "INDEX.yaml"
INDEX_MD = "INDEX.md"
STEPS_DIR = "steps"
REVIEW_TEMPLATE = "review.template.md"


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def shared_investigation_root(root: Path | None = None) -> Path:
    return (root or project_root()) / INVESTIGATION_DIR


def investigation_root(case_id: str, root: Path | None = None) -> Path:
    if not case_id:
        raise ValueError("case_id is required")
    return shared_investigation_root(root) / case_id


def step_dir(step_id: str, case_id: str, root: Path | None = None) -> Path:
    return investigation_root(case_id, root) / STEPS_DIR / normalize_step_id(step_id)


def normalize_step_id(step_id: str) -> str:
    s = step_id.strip().lower().replace(" ", "_")
    if not re.match(r"^\d{3}_", s):
        m = re.search(r"(\d+)", s)
        num = int(m.group(1)) if m else 1
        rest = re.sub(r"^step_?\d+_?", "", s, flags=re.I).strip("_") or "step"
        s = f"{num:03d}_{rest}"
    return s


def load_index(case_id: str, root: Path | None = None) -> dict[str, Any]:
    path = investigation_root(case_id, root) / INDEX_YAML
    if not path.exists():
        return {"case_id": case_id, "steps": []}
    data = yaml.safe_load(path.read_text()) or {}
    if "steps" not in data:
        data["steps"] = []
    return data


def save_index(data: dict[str, Any], case_id: str, root: Path | None = None) -> None:
    path = investigation_root(case_id, root) / INDEX_YAML
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False))


def list_cases(root: Path | None = None) -> list[str]:
    base = shared_investigation_root(root)
    if not base.exists():
        return []
    return sorted(
        child.name
        for child in base.iterdir()
        if child.is_dir() and (child / INDEX_YAML).exists()
    )


def open_step(
    step_id: str,
    *,
    case_id: str,
    hypothesis: str = "",
    expected_outcome: str = "",
    task_ref: str = "",
    root: Path | None = None,
) -> Path:
    root = root or project_root()
    sid = normalize_step_id(step_id)
    sdir = step_dir(sid, case_id, root)
    sdir.mkdir(parents=True, exist_ok=True)

    meta_path = sdir / "meta.yaml"
    if not meta_path.exists():
        meta = {
            "id": sid,
            "case_id": case_id,
            "task_ref": task_ref,
            "hypothesis": hypothesis,
            "expected_outcome": expected_outcome,
            "outcome": "open",
            "opened_at": datetime.now(UTC).isoformat(),
            "reviewer_status": "draft",
        }
        meta_path.write_text(yaml.safe_dump(meta, sort_keys=False))

    for name in ("reasoning.md", "query.cypher", "response.json"):
        p = sdir / name
        if not p.exists():
            p.write_text("" if name.endswith(".json") else f"# {sid}\n\n")

    review = sdir / "review.md"
    if not review.exists():
        tpl_path = shared_investigation_root(root) / REVIEW_TEMPLATE
        tpl = tpl_path.read_text() if tpl_path.exists() else _default_review_template()
        review.write_text(
            tpl.replace("{{step_id}}", sid)
            .replace("{{hypothesis}}", hypothesis or "_TBD_")
            .replace("{{expected_outcome}}", expected_outcome or "_TBD_")
        )

    data = load_index(case_id, root)
    data["case_id"] = case_id
    steps = data.setdefault("steps", [])
    if not any(s.get("id") == sid for s in steps):
        steps.insert(
            0,
            {
                "id": sid,
                "task_ref": task_ref,
                "hypothesis": hypothesis,
                "expected_outcome": expected_outcome,
                "outcome": "open",
                "one_line": "",
                "l3_path": investigation_l3_path(case_id, sid),
                "queries": [],
                "reviewer_status": "draft",
            },
        )
    save_index(data, case_id, root)
    return sdir


def close_step(
    step_id: str,
    *,
    case_id: str,
    outcome: str,
    one_line: str,
    queries: list[str] | None = None,
    reviewer_status: str = "ready_for_review",
    root: Path | None = None,
) -> None:
    root = root or project_root()
    sid = normalize_step_id(step_id)
    sdir = step_dir(sid, case_id, root)
    meta_path = sdir / "meta.yaml"
    meta: dict[str, Any] = {}
    if meta_path.exists():
        meta = yaml.safe_load(meta_path.read_text()) or {}
    meta["outcome"] = outcome
    meta["one_line"] = one_line
    meta["closed_at"] = datetime.now(UTC).isoformat()
    meta["reviewer_status"] = reviewer_status
    if queries:
        meta["queries"] = queries
    meta_path.write_text(yaml.safe_dump(meta, sort_keys=False))

    data = load_index(case_id, root)
    steps = data.setdefault("steps", [])
    entry = next((s for s in steps if s.get("id") == sid), None)
    if entry is None:
        entry = {"id": sid, "l3_path": investigation_l3_path(case_id, sid)}
        steps.insert(0, entry)
    entry["outcome"] = outcome
    entry["one_line"] = one_line
    entry["reviewer_status"] = reviewer_status
    if queries:
        entry["queries"] = queries
    save_index(data, case_id, root)
    render_index_md(case_id, root=root)


def render_index_md(case_id: str, root: Path | None = None) -> Path:
    root = root or project_root()
    data = load_index(case_id, root)
    out = investigation_root(case_id, root) / INDEX_MD

    lines = [
        "# Investigation recall index (L2)",
        "",
        f"**Case:** {data.get('case_id') or case_id}",
        "",
        "| Step | Outcome | Hypothesis | One-line | L3 | Review |",
        "|------|---------|------------|----------|-----|--------|",
    ]
    for s in data.get("steps", []):
        sid = s.get("id", "")
        l3 = s.get("l3_path", investigation_l3_path(case_id, sid))
        rel_review = f"steps/{sid}/review.md"
        lines.append(
            f"| [{sid}]({rel_review}) | {s.get('outcome', '')} | "
            f"{_md_cell(s.get('hypothesis', ''))} | {_md_cell(s.get('one_line', ''))} | "
            f"`{l3}` | {s.get('reviewer_status', '')} |"
        )

    lines.extend(["", "## Hypothesis coverage", ""])
    hyp_seen: dict[str, list[str]] = {}
    for s in data.get("steps", []):
        h = s.get("hypothesis") or "—"
        hyp_seen.setdefault(h[:60], []).append(s.get("id", ""))
    for h, ids in hyp_seen.items():
        lines.append(f"- **{h}** — steps: {', '.join(ids)}")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n")
    return out


def _md_cell(text: str, max_len: int = 60) -> str:
    t = (text or "").replace("|", "\\|").replace("\n", " ")
    return t if len(t) <= max_len else t[: max_len - 3] + "..."


def _default_review_template() -> str:
    return """# Step {{step_id}} — reviewer packet

## Hypothesis
{{hypothesis}}

## Expected outcome
{{expected_outcome}}

## Actual outcome
_inconclusive | confirmed | refuted_

## Summary
_One paragraph for human judges._

## Confidence
**Level:** medium
"""
