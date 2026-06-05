"""Unit tests for first-occurrence-per-tuple EVTX de-duplication.

Covers the pure rule resolution / keying and the stateful, file-order
deduplicator, plus that the collapse is surfaced in the ingest report.
"""

from __future__ import annotations

from pathlib import Path

from forensics.ingest.dedup import (
    DEFAULT_DEDUP_RULES,
    DedupRule,
    EventDeduplicator,
    dedup_key,
    resolve_dedup_rules,
)
from forensics.registry import ArtifactCheck, ArtifactStatus, IngestReport


# --- defaults match the spec -----------------------------------------------


def test_default_rules_are_the_two_known_classes():
    by_eid = {r.event_id: r for r in DEFAULT_DEDUP_RULES}
    assert by_eid[4624].keys == ("target_user", "ip", "logon_type")
    assert by_eid[3].keys == ("image", "ip", "port")


# --- dedup_key --------------------------------------------------------------


def test_dedup_key_missing_fields_become_empty_string():
    row = {"target_user": "rsydow", "ip": "10.0.0.1"}  # logon_type missing
    assert dedup_key(row, ("target_user", "ip", "logon_type")) == ("rsydow", "10.0.0.1", "")


def test_dedup_key_stringifies_values():
    row = {"image": "a.exe", "ip": "8.8.8.8", "port": 443}
    assert dedup_key(row, ("image", "ip", "port")) == ("a.exe", "8.8.8.8", "443")


# --- resolve_dedup_rules ----------------------------------------------------


def test_resolve_none_and_empty_use_defaults():
    assert resolve_dedup_rules(None) == list(DEFAULT_DEDUP_RULES)
    assert resolve_dedup_rules({}) == list(DEFAULT_DEDUP_RULES)


def test_resolve_disabled_returns_no_rules():
    assert resolve_dedup_rules({"enabled": False}) == []


def test_resolve_enabled_without_rules_keeps_defaults():
    assert resolve_dedup_rules({"enabled": True}) == list(DEFAULT_DEDUP_RULES)


def test_resolve_custom_rules_replace_defaults():
    cfg = {"rules": [{"event_id": 4625, "keys": ["target_user", "ip"], "label": "failed"}]}
    rules = resolve_dedup_rules(cfg)
    assert rules == [DedupRule(4625, ("target_user", "ip"), "failed")]


def test_resolve_skips_malformed_rules():
    cfg = {
        "rules": [
            {"event_id": 3, "keys": ["image"]},  # ok
            {"keys": ["image"]},  # no event_id -> skip
            {"event_id": 7},  # no keys -> skip
            "not-a-dict",  # skip
        ]
    }
    rules = resolve_dedup_rules(cfg)
    assert [r.event_id for r in rules] == [3]


def test_resolve_non_dict_config_uses_defaults():
    assert resolve_dedup_rules("nonsense") == list(DEFAULT_DEDUP_RULES)


# --- EventDeduplicator.keep -------------------------------------------------


def _row(eid, **kw):
    base = {"event_id": eid, "target_user": "", "ip": "", "logon_type": "", "image": "", "port": ""}
    base.update(kw)
    return base


def test_keep_first_occurrence_drops_repeats():
    d = EventDeduplicator(resolve_dedup_rules(None))
    a = _row(4624, target_user="rsydow", ip="10.0.0.1", logon_type="3")
    assert d.keep(a) is True  # first
    assert d.keep(dict(a)) is False  # exact repeat
    assert d.keep(_row(4624, target_user="rsydow", ip="10.0.0.1", logon_type="10")) is True


def test_keep_never_touches_non_deduplicated_classes():
    d = EventDeduplicator(resolve_dedup_rules(None))
    # 4688 is not a dedup class — every one passes, none recorded
    assert [d.keep(_row(4688, image="cmd.exe")) for _ in range(5)] == [True] * 5
    assert d.stats() == []
    assert d.total_dropped() == 0


def test_keep_classes_are_independent():
    d = EventDeduplicator(resolve_dedup_rules(None))
    d.keep(_row(4624, target_user="u", ip="1.1.1.1", logon_type="3"))
    d.keep(_row(4624, target_user="u", ip="1.1.1.1", logon_type="3"))  # drop
    d.keep(_row(3, image="a.exe", ip="8.8.8.8", port="443"))
    stats = {s["event_id"]: s for s in d.stats()}
    assert stats[4624]["dropped"] == 1 and stats[4624]["kept"] == 1
    assert stats[3]["dropped"] == 0 and stats[3]["kept"] == 1


def test_stats_kept_equals_unique():
    d = EventDeduplicator(resolve_dedup_rules(None))
    for lt in ("3", "3", "10", "10", "3"):
        d.keep(_row(4624, target_user="u", ip="1.1.1.1", logon_type=lt))
    s = next(x for x in d.stats() if x["event_id"] == 4624)
    assert s["kept"] == s["unique"] == 2
    assert s["dropped"] == 3


def test_collapse_is_deterministic_regardless_of_order():
    # Same multiset of events in two different orders -> identical kept/dropped
    # counts (first-seen-wins is stable on count even as the kept record varies).
    seq1 = [
        _row(4624, target_user="a", ip="1.1.1.1", logon_type="3"),
        _row(4624, target_user="b", ip="2.2.2.2", logon_type="3"),
        _row(4624, target_user="a", ip="1.1.1.1", logon_type="3"),
    ]
    seq2 = [seq1[2], seq1[1], seq1[0]]
    s1 = _run(seq1)
    s2 = _run(seq2)
    assert s1["kept"] == s2["kept"] == 2
    assert s1["dropped"] == s2["dropped"] == 1


def _run(rows):
    d = EventDeduplicator(resolve_dedup_rules(None))
    for r in rows:
        d.keep(r)
    return next(x for x in d.stats() if x["event_id"] == 4624)


def test_active_property():
    assert EventDeduplicator(resolve_dedup_rules(None)).active is True
    assert EventDeduplicator(resolve_dedup_rules({"enabled": False})).active is False


# --- report visibility ------------------------------------------------------


def test_ingest_report_serializes_dedup_when_present():
    report = IngestReport(hostname="HOST")
    check = ArtifactCheck(name="evtx", path=Path("/x/evtx.json"), status=ArtifactStatus.LOADED)
    check.dedup = [{"event_id": 4624, "label": "4624 logons", "kept": 150, "dropped": 1_600_000}]
    report.artifacts.append(check)
    out = report.to_dict()
    assert out["artifacts"][0]["dedup"][0]["dropped"] == 1_600_000


def test_ingest_report_omits_dedup_when_absent():
    report = IngestReport(hostname="HOST")
    report.artifacts.append(
        ArtifactCheck(name="netscan", path=Path("/x/n.json"), status=ArtifactStatus.LOADED)
    )
    assert "dedup" not in report.to_dict()["artifacts"][0]


# --- loader wiring ----------------------------------------------------------


class _StubCase:
    def __init__(self, evtx_dedup):
        self.evtx_dedup = evtx_dedup


def _winevtx_loader(case):
    from forensics.ingest.loaders.winevtx import WinevtxLoader

    loader = WinevtxLoader.__new__(WinevtxLoader)
    loader._case = case
    return loader


def test_loader_uses_defaults_without_case():
    assert _winevtx_loader(None).get_dedup_rules() == list(DEFAULT_DEDUP_RULES)


def test_loader_honours_case_disable():
    assert _winevtx_loader(_StubCase({"enabled": False})).get_dedup_rules() == []


def test_loader_honours_case_custom_rules():
    case = _StubCase({"rules": [{"event_id": 3, "keys": ["image", "ip", "port"]}]})
    rules = _winevtx_loader(case).get_dedup_rules()
    assert [r.event_id for r in rules] == [3]
