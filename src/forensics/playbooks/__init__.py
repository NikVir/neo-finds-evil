"""Load DFIR hunt playbooks by id."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

PLAYBOOK_DIR = Path(__file__).parent


@dataclass
class PlaybookStep:
    id: str
    hypothesis_ref: str | None
    hunt: str | None
    human_label: str
    expected_signals: str = ""
    status: str = "active"
    blocked_reason: str = ""


@dataclass
class Playbook:
    id: str
    description: str
    steps: list[PlaybookStep]


def load_playbook(playbook_id: str) -> Playbook:
    path = PLAYBOOK_DIR / f"{playbook_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Playbook not found: {playbook_id}")
    raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
    steps = []
    for s in raw.get("steps") or []:
        steps.append(
            PlaybookStep(
                id=str(s["id"]),
                hypothesis_ref=s.get("hypothesis_ref"),
                hunt=s.get("hunt"),
                human_label=str(s.get("human_label", s["id"])),
                expected_signals=str(s.get("expected_signals", "")),
                status=str(s.get("status", "active")),
                blocked_reason=str(s.get("blocked_reason", "")),
            )
        )
    return Playbook(
        id=str(raw.get("id", playbook_id)),
        description=str(raw.get("description", "")),
        steps=steps,
    )
