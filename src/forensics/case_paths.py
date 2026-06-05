"""Case-scoped investigation and Neo4j path helpers."""

from __future__ import annotations

import re
from pathlib import Path

INVESTIGATION_DIR = "investigation"
STEPS_DIR = "steps"
GRAPHS_DIR = "graphs"


def sanitize_neo4j_database(name: str) -> str:
    """Neo4j database names: alphanumeric; derive from case_id."""
    cleaned = re.sub(r"[^a-zA-Z0-9]", "", name)
    return cleaned.lower() if cleaned else "neo4j"


def investigation_dir(
    case_id: str,
    root: Path,
    *,
    override: str | None = None,
) -> Path:
    """Return per-case investigation folder under project root."""
    if override:
        p = Path(override)
        return p if p.is_absolute() else root / p
    return root / INVESTIGATION_DIR / case_id


def investigation_l3_path(case_id: str, step_id: str, *, override: str | None = None) -> str:
    """Relative L3 path string for INDEX.yaml entries."""
    if override:
        base = override.rstrip("/")
        return f"{base}/{STEPS_DIR}/{step_id}"
    return f"{INVESTIGATION_DIR}/{case_id}/{STEPS_DIR}/{step_id}"


def graphs_dir(case_id: str, root: Path, *, override: str | None = None) -> Path:
    return investigation_dir(case_id, root, override=override) / GRAPHS_DIR


def steps_dir(case_id: str, root: Path, *, override: str | None = None) -> Path:
    return investigation_dir(case_id, root, override=override) / STEPS_DIR
