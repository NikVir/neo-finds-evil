"""Tests for the vigia-cases benchmark scorer (tools/vigia_score.py).

These use synthetic fixtures (not the real dataset) so the scoring logic is
validated independently of any particular case outcome: exact vs family TTP
matching, IOC substring recall, false-positive detection, FNR-MAL, and the
specificity-gate pass/fail semantics.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# tools/ is not a package; add it to the path so we can import the scorer module.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import vigia_score as vs  # noqa: E402


def test_base_technique():
    assert vs.base_technique("T1566.001") == "T1566"
    assert vs.base_technique("t1040") == "T1040"
    assert vs.base_technique(" T1595 ") == "T1595"


def test_ttp_coverage_exact_and_family():
    # detected parent T1566 should NOT count as an exact hit for T1566.001,
    # but SHOULD count as a family hit. T1071.001 is missed entirely.
    cov = vs.ttp_coverage(
        detected=["T1566", "T1585.002"],
        expected=["T1566.001", "T1585.001", "T1071.001"],
    )
    assert cov["exact_hits"] == []
    assert cov["exact_coverage"] == pytest.approx(0.0)
    assert set(cov["family_hits"]) == {"T1566.001", "T1585.001"}
    assert cov["family_coverage"] == pytest.approx(2 / 3)


def test_ttp_coverage_exact_match():
    cov = vs.ttp_coverage(detected=["T1048", "T9999"], expected=["T1048", "T1567"])
    assert cov["exact_hits"] == ["T1048"]
    assert cov["exact_coverage"] == pytest.approx(0.5)


def test_ttp_coverage_empty_expected():
    cov = vs.ttp_coverage(detected=["T1027"], expected=[])
    assert cov["exact_coverage"] is None
    assert cov["family_coverage"] is None


def test_ioc_recall_substring():
    agent = {
        "key_iocs": ["DefaultUserName = Mr. Evil", "host N-1A9ODN6ZXK4LQ"],
        "claims": [{"claim": "email mrevilrulez@yahoo.com seen", "status": "CONFIRMED"}],
    }
    truth_iocs = [
        {"type": "email", "value": "mrevilrulez@yahoo.com"},
        {"type": "hostname", "value": "N-1A9ODN6ZXK4LQ"},
        {"type": "ip_address", "value": "192.168.1.111"},  # absent -> missing
    ]
    rec = vs.ioc_recall(agent, truth_iocs)
    assert rec["n_canonical"] == 3
    assert rec["n_recovered"] == 2
    assert rec["recall"] == pytest.approx(2 / 3)
    assert "192.168.1.111" in rec["missing"]


def test_ioc_recall_no_canonical():
    rec = vs.ioc_recall({"key_iocs": ["whatever"]}, [])
    assert rec["recall"] is None


# --- end-to-end fixtures -------------------------------------------------------

def _write_case(results: Path, truth: Path, case_id: str, verdict_obj: dict, truth_obj: dict):
    (results / f"{case_id}.verdict.json").write_text(json.dumps(verdict_obj), encoding="utf-8")
    (truth / case_id).mkdir(parents=True, exist_ok=True)
    (truth / case_id / "ground_truth.json").write_text(json.dumps(truth_obj), encoding="utf-8")


def _build(tmp_path: Path, gate_verdict: str, sa_overrides: dict | None = None):
    """Build a full fixture set: 3 MALICE score_against cases + the 005 gate.

    sa_overrides maps a score_against case_id -> agent verdict string.
    """
    results = tmp_path / "results"
    truth = tmp_path / "truth"
    results.mkdir()
    truth.mkdir()
    overrides = sa_overrides or {}
    for case_id in vs.SCORE_AGAINST:
        agent_v = overrides.get(case_id, "MALICE")
        _write_case(
            results, truth, case_id,
            {"case_id": case_id, "verdict": agent_v, "confidence": 0.9,
             "mitre_ttps": ["T1048"], "key_iocs": ["spy@nist.gov"], "claims": []},
            {"case_id": case_id, "verdict": "MALICE",
             "mitre_ttps": ["T1048", "T1567"],
             "key_iocs": [{"type": "email", "value": "spy@nist.gov"}]},
        )
    # 005 gate: ground truth SUSPICION, no canonical IOCs.
    _write_case(
        results, truth, "VIGIA-REAL-005",
        {"case_id": "VIGIA-REAL-005", "verdict": gate_verdict, "confidence": 0.6,
         "mitre_ttps": ["T1027"], "key_iocs": [], "claims": []},
        {"case_id": "VIGIA-REAL-005", "verdict": "SUSPICION",
         "mitre_ttps": ["T1027", "T1486"], "key_iocs": []},
    )
    return results, truth


def test_perfect_run_with_gate_pass(tmp_path):
    results, truth = _build(tmp_path, gate_verdict="SUSPICION")
    rep = vs.score_benchmark(results, truth, "test-agent", "2026-06-09")
    assert rep["summary"]["verdict_accuracy"] == pytest.approx(1.0)
    assert rep["summary"]["fnr_mal"] == pytest.approx(0.0)
    # exact ttp: detected T1048 over expected {T1048,T1567} -> 1/2 each, pooled 3/6.
    assert rep["summary"]["ttp_coverage"] == pytest.approx(0.5)
    # FPR basis is the SUSPICION-truth gate case; SUSPICION verdict is not an over-call.
    assert rep["false_positive_basis"]["eligible_cases"] == ["VIGIA-REAL-005"]
    assert rep["summary"]["fpr"] == pytest.approx(0.0)
    gate = rep["specificity_gate"][0]
    assert gate["passed"] is True
    assert gate["over_called_malice"] is False
    assert rep["thresholds_met"]["verdict_accuracy"] is True


def test_gate_overcall_is_false_positive(tmp_path):
    results, truth = _build(tmp_path, gate_verdict="MALICE")
    rep = vs.score_benchmark(results, truth, "test-agent", "2026-06-09")
    # Headline accuracy must be unaffected by the gate.
    assert rep["summary"]["verdict_accuracy"] == pytest.approx(1.0)
    # But the gate fails and drives FPR to 1.0 over its (single) eligible case.
    gate = rep["specificity_gate"][0]
    assert gate["passed"] is False
    assert gate["over_called_malice"] is True
    assert rep["false_positive_basis"]["false_positives"] == ["VIGIA-REAL-005"]
    assert rep["summary"]["fpr"] == pytest.approx(1.0)
    assert rep["thresholds_met"]["fpr"] is False


def test_fnr_mal_when_malice_called_benign(tmp_path):
    results, truth = _build(tmp_path, gate_verdict="SUSPICION",
                            sa_overrides={"VIGIA-REAL-001": "BENIGN"})
    rep = vs.score_benchmark(results, truth, "test-agent", "2026-06-09")
    assert rep["summary"]["verdict_accuracy"] == pytest.approx(2 / 3)
    assert rep["summary"]["fnr_mal"] == pytest.approx(1 / 3)
    assert rep["thresholds_met"]["fnr_mal"] is False


def test_determinism(tmp_path):
    results, truth = _build(tmp_path, gate_verdict="SUSPICION")
    a = vs.score_benchmark(results, truth, "test-agent", "2026-06-09")
    b = vs.score_benchmark(results, truth, "test-agent", "2026-06-09")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
