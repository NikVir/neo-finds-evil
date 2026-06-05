"""First-occurrence-per-tuple de-duplication for high-volume EVTX classes.

Some Windows/Sysmon event classes are extremely high *volume* but low
*information* for the hunts. On a domain controller the Security log can hold
~1.6M routine 4624 logons that collapse to ~150 distinct
``(user, source-IP, logon-type)`` tuples; Sysmon EID 3 network-connection
events run into the hundreds of thousands per workstation and collapse to a
few dozen ``(image, dest-IP, dest-port)`` tuples. Loading every repeat drowns
the graph and stalls ingest.

**Why first-occurrence-per-tuple is correct.** The hunts reason over distinct
*who / where / how* relationships, not event volume — e.g. ``lateral_logons``
groups logons by (user, ip, logonType) and ``external_connections`` groups by
(process, ip, port). Keeping the **first** occurrence of each tuple therefore
preserves every relationship a hunt traverses while dropping pure repeats.
"First" means first seen in file (stream) order, so the collapse is fully
**deterministic**. Only the event classes named in the rule set are touched;
every other event is passed through untouched.

**Configuration.** Rules are data, not hardcoded behaviour, so they are
auditable and extensible. Defaults live in :data:`DEFAULT_DEDUP_RULES` and can
be overridden per case under an ``evtx_dedup`` key in the case YAML::

    evtx_dedup:
      enabled: true            # optional; default true
      rules:                   # optional; if present, replaces the defaults
        - event_id: 4624
          keys: [target_user, ip, logon_type]
          label: "4624 logons"
        - event_id: 3
          keys: [image, ip, port]
          label: "sysmon network connections"

Keys are the loader's *normalized* row-field names (what gets stored on the
WindowsEvent node), which map to the raw EventData fields as follows:

==========  ==================  ==========================================
event_id    normalized key      raw EventData field(s)
==========  ==================  ==========================================
4624        target_user         TargetUserName / SubjectUserName
4624        ip                  IpAddress
4624        logon_type          LogonType
3           image               Image
3           ip                  DestinationIp
3           port                DestinationPort
==========  ==================  ==========================================
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DedupRule:
    """One high-volume class to collapse to first-occurrence-per-tuple."""

    event_id: int
    keys: tuple[str, ...]
    label: str = ""

    def display(self) -> str:
        return self.label or f"event {self.event_id}"


# Built-in defaults — the two classes we have been collapsing by hand.
# Expressed in normalized row-field names (see module docstring for mapping).
DEFAULT_DEDUP_RULES: tuple[DedupRule, ...] = (
    DedupRule(4624, ("target_user", "ip", "logon_type"), "4624 logons"),
    DedupRule(3, ("image", "ip", "port"), "sysmon network connections"),
)


def dedup_key(row: dict, keys: tuple[str, ...]) -> tuple[str, ...]:
    """Stable tuple key from a row's normalized fields (missing -> '')."""
    return tuple(str(row.get(k) or "") for k in keys)


def resolve_dedup_rules(config: object | None) -> list[DedupRule]:
    """Resolve dedup rules from optional case config.

    - ``None`` / ``{}``                -> built-in defaults
    - ``{enabled: false}``             -> no dedup (empty list)
    - ``{rules: [...]}``               -> exactly those rules (replaces defaults)
    - ``{enabled: true}`` (no rules)   -> built-in defaults
    """
    if not config:
        return list(DEFAULT_DEDUP_RULES)
    if not isinstance(config, dict):
        return list(DEFAULT_DEDUP_RULES)
    if config.get("enabled", True) is False:
        return []
    raw_rules = config.get("rules")
    if not raw_rules:
        return list(DEFAULT_DEDUP_RULES)
    rules: list[DedupRule] = []
    for r in raw_rules:
        if not isinstance(r, dict):
            continue
        eid = r.get("event_id")
        keys = r.get("keys") or []
        if eid is None or not keys:
            continue
        rules.append(
            DedupRule(
                event_id=int(eid),
                keys=tuple(str(k) for k in keys),
                label=str(r.get("label", "")),
            )
        )
    return rules


@dataclass
class _Counter:
    kept: int = 0
    dropped: int = 0
    seen: set = field(default_factory=set)


class EventDeduplicator:
    """Stateful, file-order first-occurrence-per-tuple filter.

    Construct once per host/load. Call :meth:`keep` for every event row in
    stream order; it returns ``True`` for the first sighting of each tuple of
    a deduplicated class and for *all* events of non-deduplicated classes, and
    ``False`` for subsequent repeats. :meth:`stats` reports the collapse.
    """

    def __init__(self, rules: list[DedupRule] | tuple[DedupRule, ...]) -> None:
        self._rules: dict[int, DedupRule] = {r.event_id: r for r in rules}
        self._counts: dict[int, _Counter] = {r.event_id: _Counter() for r in rules}

    @property
    def active(self) -> bool:
        return bool(self._rules)

    def keep(self, row: dict) -> bool:
        """Return whether this event row should be ingested.

        Non-deduplicated classes are never touched (always kept, never
        counted). Deduplicated classes keep only the first occurrence per
        tuple, in stream order.
        """
        rule = self._rules.get(row.get("event_id"))
        if rule is None:
            return True
        counter = self._counts[rule.event_id]
        key = dedup_key(row, rule.keys)
        if key in counter.seen:
            counter.dropped += 1
            return False
        counter.seen.add(key)
        counter.kept += 1
        return True

    def stats(self) -> list[dict]:
        """Per-class collapse stats, for classes that saw at least one event.

        ``kept`` equals ``unique`` by construction (first-occurrence-per-tuple),
        both are reported for clarity alongside ``dropped``.
        """
        out: list[dict] = []
        for eid, rule in self._rules.items():
            c = self._counts[eid]
            if c.kept == 0 and c.dropped == 0:
                continue
            out.append(
                {
                    "event_id": eid,
                    "label": rule.display(),
                    "keys": list(rule.keys),
                    "kept": c.kept,
                    "dropped": c.dropped,
                    "unique": len(c.seen),
                }
            )
        return out

    def total_dropped(self) -> int:
        return sum(c.dropped for c in self._counts.values())
