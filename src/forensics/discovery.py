"""Multi-strategy path matching and discovery scoring."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from forensics.case import CaseManifest
from forensics.sensitive import glob_to_regex, path_matches_sensitive


@dataclass
class DiscoveryConfig:
    roots: list[str] = field(default_factory=list)
    token_keywords: list[str] = field(default_factory=list)
    path_aliases: dict[str, list[str]] = field(default_factory=dict)
    min_keyword_len: int = 4
    exclude_patterns: list[str] = field(default_factory=list)


def discovery_from_case(case: CaseManifest) -> DiscoveryConfig:
    raw = getattr(case, "discovery", None) or {}
    if not isinstance(raw, dict):
        raw = {}
    return DiscoveryConfig(
        roots=[str(x) for x in (raw.get("roots") or [])],
        token_keywords=[str(x) for x in (raw.get("token_keywords") or case.filename_keywords)],
        path_aliases={
            str(k): [str(v) for v in vals] for k, vals in (raw.get("path_aliases") or {}).items()
        },
        min_keyword_len=int(raw.get("min_keyword_len", 4)),
        exclude_patterns=[str(x) for x in (raw.get("exclude_patterns") or [])],
    )


def _word_boundary_match(text: str, keyword: str) -> bool:
    if len(keyword) < 2:
        return False
    pat = re.compile(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", re.IGNORECASE)
    return bool(pat.search(text))


def _is_excluded(norm: str, exclude_patterns: list[str]) -> bool:
    low = norm.lower()
    defaults = (
        "windows/winsxs",
        "program files/windowsapps",
        "windows/system32",
        "windows/servicing",
    )
    for pat in list(exclude_patterns) + list(defaults):
        if pat.replace("\\", "/").lower() in low:
            return True
    return False


def match_score(
    path: str,
    case: CaseManifest,
    discovery: DiscoveryConfig | None = None,
) -> float:
    """Score 0.0–1.0 how interesting a path is for the case."""
    if not path:
        return 0.0
    disc = discovery or discovery_from_case(case)
    norm = path.replace("\\", "/")
    if _is_excluded(norm, disc.exclude_patterns):
        return 0.0

    score = 0.0
    if path_matches_sensitive(path, case.sensitive_paths, case.sensitive_extensions):
        score = max(score, 0.85)

    low = norm.lower()
    for kw in disc.token_keywords:
        k = kw.lower()
        if len(k) < disc.min_keyword_len:
            continue
        if _word_boundary_match(low, k):
            score = max(score, 0.7)
        elif k in low and len(k) >= disc.min_keyword_len:
            score = max(score, 0.55)

    for alias_key, aliases in disc.path_aliases.items():
        terms = [alias_key.lower(), *[a.lower() for a in aliases]]
        for term in terms:
            if len(term) >= disc.min_keyword_len and term in low:
                score = max(score, 0.75)

    for root in disc.roots:
        rx = glob_to_regex(root.replace("\\", "/"))
        if rx.search(norm):
            score = max(score, 0.4)

    return min(score, 1.0)


def collect_discovery_seeds(case: CaseManifest, client, hostname: str) -> set[str]:
    """Paths and fragments to seed MFT lazy / psort filters."""
    seeds: set[str] = set()
    disc = discovery_from_case(case)
    for root in disc.roots:
        seeds.add(root.replace("/", "\\"))
    for kw in disc.token_keywords:
        if len(kw) >= disc.min_keyword_len:
            seeds.add(kw)
    for alias_key, aliases in disc.path_aliases.items():
        seeds.add(alias_key)
        seeds.update(aliases)
    for pat in case.sensitive_paths:
        frag = pat.replace("*", "").strip("\\/")
        if frag:
            seeds.add(frag)

    prefix = f"{hostname}:"
    for rec in client.query(
        """
        MATCH (f:File) WHERE f.id STARTS WITH $prefix AND f.path IS NOT NULL
        RETURN f.path AS path LIMIT 5000
        """,
        {"prefix": prefix},
    ):
        p = str(rec.get("path") or "")
        if p:
            seeds.add(p.replace("/", "\\"))
    for rec in client.query(
        """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $hostname})
        WHERE e.eventId IN [1, 11, 23]
        RETURN e.commandLine AS cmd, e.image AS image LIMIT 2000
        """,
        {"hostname": hostname},
    ):
        for val in (rec.get("cmd"), rec.get("image")):
            if val and "\\" in str(val):
                seeds.add(str(val).split('"')[0] if '"' in str(val) else str(val))
    return seeds
