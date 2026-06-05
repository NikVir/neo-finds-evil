"""Progressive ingest tier resolution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ALL_ARTIFACT_NAMES = frozenset(
    {
        "pslist",
        "dlllist",
        "netscan",
        "evtx",
        "shimcache",
        "prefetch",
        "path_catalog",
        "mft",
        "media_exif",
        "usb",
        "bulk",
    }
)

TIER_ORDER = ("triage", "execution", "filesystem", "exfil", "full")
DEFAULT_TIER = "triage"
_CONFIG_PATH = Path(__file__).resolve().parents[3] / "config" / "ingest_tiers.yaml"


@dataclass(frozen=True)
class TierPlan:
    tier: str
    artifacts: frozenset[str]
    evtx_packs: frozenset[str] | None
    is_full: bool


def _load_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or _CONFIG_PATH
    if not cfg_path.exists():
        return {}
    return yaml.safe_load(cfg_path.read_text()) or {}


def _all_loader_names() -> frozenset[str]:
    return ALL_ARTIFACT_NAMES


def _cumulative_artifacts(cfg: dict[str, Any], tier: str) -> frozenset[str]:
    tiers = cfg.get("tiers") or {}
    if tier == "full" or (tiers.get("full") or {}).get("all"):
        if tier == "full":
            return _all_loader_names()
    names: set[str] = set()
    for name in TIER_ORDER:
        spec = tiers.get(name) or {}
        if spec.get("all"):
            return _all_loader_names()
        if "artifacts" in spec:
            names.update(str(a) for a in spec["artifacts"])
        if "adds" in spec:
            names.update(str(a) for a in spec["adds"])
        if name == tier:
            break
    return frozenset(names)


def _profile_key(case_type: str, event_profile_override: str = "") -> str:
    if event_profile_override:
        return event_profile_override
    return case_type


def evtx_packs_for_tier(
    tier: str,
    case_type: str,
    *,
    event_profile_override: str = "",
    config: dict[str, Any] | None = None,
) -> frozenset[str] | None:
    """Return EVTX pack filter for tier, or None for full profile (tier full / explicit only)."""
    if tier == "full":
        return None
    cfg = config or _load_config()
    packs_cfg = cfg.get("triage_evtx_packs") or {}
    key = _profile_key(case_type, event_profile_override)
    packs = packs_cfg.get(key) or packs_cfg.get(case_type) or packs_cfg.get("intrusion")
    if not packs:
        return None
    return frozenset(str(p) for p in packs)


def resolve_tier_plan(
    tier: str | None,
    case_type: str,
    *,
    event_profile_override: str = "",
    only: set[str] | None = None,
    full: bool = False,
    config: dict[str, Any] | None = None,
) -> TierPlan:
    """Resolve ingest tier to artifact set and EVTX pack filter."""
    if only is not None:
        return TierPlan(
            tier="custom",
            artifacts=frozenset(only),
            evtx_packs=evtx_packs_for_tier(
                DEFAULT_TIER,
                case_type,
                event_profile_override=event_profile_override,
                config=config,
            )
            if "evtx" in only
            else None,
            is_full=False,
        )
    resolved = "full" if full else (tier or DEFAULT_TIER)
    if resolved not in TIER_ORDER:
        raise ValueError(f"Unknown ingest tier: {resolved}. Choose from: {', '.join(TIER_ORDER)}")
    cfg = config or _load_config()
    artifacts = _cumulative_artifacts(cfg, resolved)
    packs = evtx_packs_for_tier(
        resolved,
        case_type,
        event_profile_override=event_profile_override,
        config=cfg,
    )
    return TierPlan(
        tier=resolved,
        artifacts=artifacts,
        evtx_packs=packs,
        is_full=resolved == "full",
    )


def triage_playbook_steps(case_type: str, config: dict[str, Any] | None = None) -> list[str]:
    cfg = config or _load_config()
    steps = (cfg.get("triage_playbook_steps") or {}).get(case_type)
    if steps:
        return [str(s) for s in steps]
    return list((cfg.get("triage_playbook_steps") or {}).get("intrusion") or [])


def execution_playbook_steps(case_type: str, config: dict[str, Any] | None = None) -> list[str]:
    cfg = config or _load_config()
    steps = (cfg.get("execution_playbook_steps") or {}).get(case_type)
    if steps:
        return [str(s) for s in steps]
    return list((cfg.get("execution_playbook_steps") or {}).get("intrusion") or [])


def playbook_steps_for_tier(
    case_type: str, tier: str, config: dict[str, Any] | None = None
) -> list[str]:
    """Cumulative playbook step ids unlocked at a tier (triage ⊆ execution ⊆ ...)."""
    cfg = config or _load_config()
    steps = list(triage_playbook_steps(case_type, cfg))
    if tier in ("execution", "filesystem", "exfil", "full"):
        for s in execution_playbook_steps(case_type, cfg):
            if s not in steps:
                steps.append(s)
    return steps


def tier_for_artifacts(artifacts: frozenset[str], config: dict[str, Any] | None = None) -> str:
    """Minimum tier name that includes all given artifacts."""
    cfg = config or _load_config()
    for name in TIER_ORDER:
        if artifacts <= _cumulative_artifacts(cfg, name):
            return name
    return "full"


def next_tier(current: str) -> str | None:
    try:
        idx = TIER_ORDER.index(current)
    except ValueError:
        return DEFAULT_TIER
    if idx + 1 < len(TIER_ORDER):
        return TIER_ORDER[idx + 1]
    return None
