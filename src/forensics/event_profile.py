"""Load EVTX event taxonomy profiles and build Plaso psort filters."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PROFILE_DIR = Path(__file__).resolve().parents[2] / "config" / "event_profiles"


@dataclass
class EventSpec:
    pack: str
    plaso_source: str
    eid: int
    name: str
    xml_fields: list[str] = field(default_factory=list)


@dataclass
class EventProfile:
    id: str
    description: str
    events: list[EventSpec]


def _load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}


def _parse_events(raw_events: list[dict]) -> list[EventSpec]:
    out: list[EventSpec] = []
    for e in raw_events:
        out.append(
            EventSpec(
                pack=str(e.get("pack", "default")),
                plaso_source=str(e["plaso_source"]),
                eid=int(e["eid"]),
                name=str(e.get("name", "")),
                xml_fields=[str(f) for f in (e.get("xml_fields") or [])],
            )
        )
    return out


def load_profile(profile_id: str, profile_dir: Path | None = None) -> EventProfile:
    root = profile_dir or PROFILE_DIR
    path = root / f"{profile_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Event profile not found: {profile_id}")

    raw = _load_yaml(path)
    events: list[EventSpec] = []

    if raw.get("extends"):
        base = load_profile(str(raw["extends"]), root)
        events.extend(base.events)

    if raw.get("events"):
        events.extend(_parse_events(raw["events"]))

    include_packs = raw.get("include_packs")
    if include_packs and raw.get("extends"):
        packs = {str(p) for p in include_packs}
        events = [e for e in events if e.pack in packs]

    # Dedupe by (source, eid)
    seen: set[tuple[str, int]] = set()
    deduped: list[EventSpec] = []
    for e in events:
        key = (e.plaso_source, e.eid)
        if key not in seen:
            seen.add(key)
            deduped.append(e)

    return EventProfile(
        id=str(raw.get("id", profile_id)),
        description=str(raw.get("description", "")),
        events=deduped,
    )


def profile_for_case_type(case_type: str) -> EventProfile:
    mapping = {
        "intrusion": "intrusion",
        "legacy_intrusion": "legacy_intrusion",
        "insider_ip_theft": "insider_ip_theft",
        "account_compromise": "account_compromise",
        "hybrid": "intrusion",
    }
    return load_profile(mapping.get(case_type, "base_windows"))


def allowed_eids(profile: EventProfile) -> frozenset[int]:
    return frozenset(e.eid for e in profile.events)


def allowed_eids_for_packs(
    profile: EventProfile, packs: frozenset[str] | None
) -> frozenset[int]:
    if not packs:
        return allowed_eids(profile)
    return frozenset(e.eid for e in profile.events if e.pack in packs)


def plaso_filter_clause(spec: EventSpec) -> str:
    return f'(source_name is "{spec.plaso_source}" and event_identifier is {spec.eid})'


def build_psort_evtx_filter(
    profile: EventProfile,
    *,
    date_filter: str | None = None,
) -> str:
    """Build Plaso filter for windows:evtx:record matching profile events."""
    clauses = [plaso_filter_clause(e) for e in profile.events]
    core = 'data_type is "windows:evtx:record" and (' + " or ".join(clauses) + ")"
    if date_filter:
        return f"{date_filter} and {core}"
    return core


def build_psort_filter_by_pack(
    profile: EventProfile,
    pack: str,
    *,
    date_filter: str | None = None,
) -> str:
    events = [e for e in profile.events if e.pack == pack]
    if not events:
        raise ValueError(f"No events in pack {pack}")
    sub = EventProfile(id=pack, description="", events=events)
    return build_psort_evtx_filter(sub, date_filter=date_filter)


def all_xml_field_names(profile: EventProfile) -> set[str]:
    names: set[str] = set()
    for e in profile.events:
        names.update(e.xml_fields)
    return names
