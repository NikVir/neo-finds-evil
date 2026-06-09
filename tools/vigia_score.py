#!/usr/bin/env python3
"""Deterministic scorer for the vigia-cases benchmark.

Compares this project's agent verdicts -- produced *blind* from each case's
``case.json`` (see ``docs/accuracy-report.md`` -> "Benchmark: vigia-cases") --
against the canonical ``ground_truth.json`` from Anna Tchijova's vigia-cases
dataset, computing the metrics defined in the dataset's ``SCORING_GUIDE.md``.

Ground truth is read ONLY here, in the scoring step. It is never exposed to the
agent during verdict production; that isolation is what makes the benchmark
meaningful (any leak invalidates it).

Dataset: https://github.com/annatchijova/vigia-cases (Apache-2.0)
  Tchijova, A. (2026). vigia-cases: DFIR Benchmark Dataset for Forensic Intent
  Analysis. SANS FIND EVIL Hackathon 2026.

This scorer is deterministic: same inputs -> byte-identical report (the only
non-deterministic field, ``evaluation_date``, is supplied by the caller).

Usage:
    python tools/vigia_score.py \
        --results ~/vigia-eval/results \
        --truth   ~/vigia-eval/truth \
        --out     ~/vigia-eval/vigia-report.json \
        --date    2026-06-09
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# --- Benchmark configuration (fixed for this dataset; see vigia-cases/index.json) ---
# Only `score_against` cases are valid for headline accuracy claims.
SCORE_AGAINST = ("VIGIA-REAL-001", "VIGIA-REAL-002", "VIGIA-REAL-007")
# VIGIA-REAL-005 is the intentional false-positive gate (ground truth SUSPICION).
# It is reported separately and NEVER folded into the headline accuracy number.
SPECIFICITY_GATE = ("VIGIA-REAL-005",)

# Verdict severity ordering for false-positive detection. ABSTAIN is handled
# separately (it is not an over-call).
SEVERITY = {"BENIGN": 0, "SUSPICION": 1, "MALICE": 2}

# Thresholds from vigia-cases/SCORING_GUIDE.md.
THRESHOLDS = {
    "verdict_accuracy": 0.80,  # >=
    "fpr": 0.20,               # <=
    "fnr_mal": 0.10,           # <=
    "ttp_coverage": 0.60,      # >=
}


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def base_technique(ttp: str) -> str:
    """Return the parent ATT&CK technique id (drop the ``.NNN`` sub-technique)."""
    return ttp.strip().upper().split(".")[0]


def ttp_coverage(detected: list[str], expected: list[str]) -> dict:
    """Exact and family-level (parent-technique) TTP coverage for one case.

    Exact matching mirrors SCORING_GUIDE.md's own worked example
    (|detected & expected| / |expected|). Family matching additionally credits a
    detected technique whose *parent* matches an expected technique's parent
    (e.g. detected T1566 covers expected T1566.001) -- reported as an honest,
    more lenient secondary view, never as the headline number.
    """
    det = {t.strip().upper() for t in detected}
    exp = [t.strip().upper() for t in expected]
    exp_set = set(exp)
    exact_hits = sorted(det & exp_set)

    det_bases = {base_technique(t) for t in det}
    family_hits = sorted(e for e in exp_set if base_technique(e) in det_bases)

    n = len(exp_set)
    return {
        "expected": sorted(exp_set),
        "detected": sorted(det),
        "exact_hits": exact_hits,
        "family_hits": family_hits,
        "exact_coverage": (len(exact_hits) / n) if n else None,
        "family_coverage": (len(family_hits) / n) if n else None,
        "n_expected": n,
        "n_exact": len(exact_hits),
        "n_family": len(family_hits),
    }


def ioc_recall(agent_verdict: dict, truth_iocs: list[dict]) -> dict:
    """Fraction of canonical IOC *values* that appear anywhere in the agent output.

    The agent emits IOCs as free strings while ground truth stores
    ``{type, value, context}``. We serialize the entire agent verdict to a
    lowercased blob and test each canonical IOC value as a case-insensitive
    substring -- charitable to format differences, and fully deterministic.
    Cases whose ground truth has no canonical IOCs are reported as N/A.
    """
    blob = json.dumps(agent_verdict, ensure_ascii=False).lower()
    total = len(truth_iocs)
    recovered, missing = [], []
    for ioc in truth_iocs:
        value = str(ioc.get("value", "")).strip()
        if value and value.lower() in blob:
            recovered.append(value)
        else:
            missing.append(value)
    return {
        "n_canonical": total,
        "n_recovered": len(recovered),
        "recall": (len(recovered) / total) if total else None,
        "recovered": recovered,
        "missing": missing,
    }


def score_benchmark(results_dir: Path, truth_dir: Path, agent_id: str, eval_date: str) -> dict:
    """Compute the full benchmark report. Pure function of its inputs + the date."""
    cases = SCORE_AGAINST + SPECIFICITY_GATE

    verdicts: dict[str, dict] = {}
    truths: dict[str, dict] = {}
    for case_id in cases:
        verdicts[case_id] = load_json(results_dir / f"{case_id}.verdict.json")
        truths[case_id] = load_json(truth_dir / case_id / "ground_truth.json")

    # ---- Headline: score_against tier ----
    sa_results = []
    correct = 0
    pooled_exact_hits = pooled_family_hits = pooled_expected = 0
    for case_id in SCORE_AGAINST:
        v, t = verdicts[case_id], truths[case_id]
        agent_verdict = v["verdict"].strip().upper()
        expected = t["verdict"].strip().upper()
        is_correct = agent_verdict == expected
        correct += int(is_correct)
        cov = ttp_coverage(v.get("mitre_ttps", []), t.get("mitre_ttps", []))
        pooled_exact_hits += cov["n_exact"]
        pooled_family_hits += cov["n_family"]
        pooled_expected += cov["n_expected"]
        sa_results.append({
            "case_id": case_id,
            "agent_verdict": agent_verdict,
            "expected_verdict": expected,
            "agent_confidence": v.get("confidence"),
            "correct": is_correct,
            "mitre_ttps_detected": cov["detected"],
            "mitre_ttps_expected": cov["expected"],
            "ttp_exact_coverage": cov["exact_coverage"],
            "ttp_family_coverage": cov["family_coverage"],
            "ioc_recall": ioc_recall(v, t.get("key_iocs", [])),
        })

    n_sa = len(SCORE_AGAINST)
    verdict_accuracy = correct / n_sa if n_sa else None
    ttp_cov_exact = pooled_exact_hits / pooled_expected if pooled_expected else None
    ttp_cov_family = pooled_family_hits / pooled_expected if pooled_expected else None

    # FNR-MAL over score_against MALICE-truth cases: MALICE mis-called as BENIGN.
    mal_cases = [c for c in SCORE_AGAINST if truths[c]["verdict"].strip().upper() == "MALICE"]
    fn_mal = sum(1 for c in mal_cases if verdicts[c]["verdict"].strip().upper() == "BENIGN")
    fnr_mal = fn_mal / len(mal_cases) if mal_cases else None

    # ---- False-positive rate over ALL evaluated cases whose truth is BENIGN/SUSPICION ----
    # A false positive = agent escalated above the truth severity (e.g. SUSPICION
    # truth called MALICE; BENIGN truth called SUSPICION/MALICE).
    fp_eligible, false_positives = [], []
    for case_id in cases:
        expected = truths[case_id]["verdict"].strip().upper()
        if expected in ("BENIGN", "SUSPICION"):
            fp_eligible.append(case_id)
            agent_verdict = verdicts[case_id]["verdict"].strip().upper()
            if agent_verdict in SEVERITY and SEVERITY[agent_verdict] > SEVERITY[expected]:
                false_positives.append(case_id)
    fpr = (len(false_positives) / len(fp_eligible)) if fp_eligible else None

    # ---- Specificity gate (VIGIA-REAL-005), reported separately ----
    gate_blocks = []
    for case_id in SPECIFICITY_GATE:
        v, t = verdicts[case_id], truths[case_id]
        agent_verdict = v["verdict"].strip().upper()
        expected = t["verdict"].strip().upper()
        cov = ttp_coverage(v.get("mitre_ttps", []), t.get("mitre_ttps", []))
        over_called = agent_verdict == "MALICE"
        passed = agent_verdict in ("SUSPICION", "ABSTAIN")  # per SCORING_GUIDE + ToDo
        gate_blocks.append({
            "case_id": case_id,
            "agent_verdict": agent_verdict,
            "expected_verdict": expected,
            "exact_match": agent_verdict == expected,
            "passed": passed,
            "over_called_malice": over_called,
            "agent_confidence": v.get("confidence"),
            "mitre_ttps_detected": cov["detected"],
            "mitre_ttps_expected": cov["expected"],
            "ttp_exact_coverage": cov["exact_coverage"],
            "ttp_family_coverage": cov["family_coverage"],
        })

    # ---- Secondary metrics ----
    abstentions = [c for c in cases if verdicts[c]["verdict"].strip().upper() == "ABSTAIN"]
    ioc_aggregate_total = ioc_aggregate_hit = 0
    for case_id in cases:
        rec = ioc_recall(verdicts[case_id], truths[case_id].get("key_iocs", []))
        ioc_aggregate_total += rec["n_canonical"]
        ioc_aggregate_hit += rec["n_recovered"]

    report = {
        "agent_id": agent_id,
        "evaluation_date": eval_date,
        "dataset": {
            "name": "vigia-cases",
            "repo": "https://github.com/annatchijova/vigia-cases",
            "commit": "5453805",
            "license": "Apache-2.0",
            "citation": (
                "Tchijova, A. (2026). vigia-cases: DFIR Benchmark Dataset for "
                "Forensic Intent Analysis. SANS FIND EVIL Hackathon 2026."
            ),
        },
        "tier": "score_against",
        "cases_evaluated": n_sa,
        "results": sa_results,
        "summary": {
            "verdict_accuracy": verdict_accuracy,
            "fpr": fpr,
            "fnr_mal": fnr_mal,
            "ttp_coverage": ttp_cov_exact,
            "ttp_coverage_family": ttp_cov_family,
            "_fpr_basis": (
                "Computed over BENIGN/SUSPICION-truth cases across the whole "
                f"evaluation: {fp_eligible or 'none'}. No FP-eligible cases exist "
                "within the score_against tier itself."
            ),
        },
        "specificity_gate": gate_blocks,
        "false_positive_basis": {
            "eligible_cases": fp_eligible,
            "false_positives": false_positives,
            "fpr": fpr,
        },
        "secondary_metrics": {
            "peirce_alignment": None,
            "peirce_note": (
                "Not deterministically scorable: the agent's verdict schema did not "
                "re-emit a Firstness/Secondness/Thirdness classification, and ground "
                "truth stores Peirce layers as free-text narratives. case.json tags "
                "each artifact with a peirce_layer, but no machine-checkable agent "
                "classification was produced to compare against."
            ),
            "ioc_recall": {
                "aggregate_recall": (
                    ioc_aggregate_hit / ioc_aggregate_total if ioc_aggregate_total else None
                ),
                "n_canonical": ioc_aggregate_total,
                "n_recovered": ioc_aggregate_hit,
                "per_case": {
                    c: ioc_recall(verdicts[c], truths[c].get("key_iocs", [])) for c in cases
                },
            },
            "abstention_rate": len(abstentions) / len(cases) if cases else None,
            "abstentions": abstentions,
            "abstention_note": (
                "No evaluated case has an abstain-expected ground truth, so a correct "
                "abstention was never available; this rate is reported for completeness."
            ),
        },
        "thresholds": THRESHOLDS,
        "thresholds_met": {
            "verdict_accuracy": (
                verdict_accuracy is not None and verdict_accuracy >= THRESHOLDS["verdict_accuracy"]
            ),
            "fpr": fpr is not None and fpr <= THRESHOLDS["fpr"],
            "fnr_mal": fnr_mal is not None and fnr_mal <= THRESHOLDS["fnr_mal"],
            "ttp_coverage": (
                ttp_cov_exact is not None and ttp_cov_exact >= THRESHOLDS["ttp_coverage"]
            ),
        },
    }
    return report


def _fmt_pct(x: float | None) -> str:
    return "N/A" if x is None else f"{x * 100:.1f}%"


def print_summary(report: dict) -> None:
    s = report["summary"]
    print(f"agent: {report['agent_id']}   date: {report['evaluation_date']}")
    print(f"dataset: vigia-cases @ {report['dataset']['commit']} (Tchijova 2026, Apache-2.0)")
    print("\n== Headline (score_against: VIGIA-REAL-001/002/007) ==")
    for r in report["results"]:
        flag = "OK " if r["correct"] else "XX "
        print(
            f"  {flag}{r['case_id']}: agent={r['agent_verdict']} "
            f"expected={r['expected_verdict']} conf={r['agent_confidence']} "
            f"ttp_exact={_fmt_pct(r['ttp_exact_coverage'])}"
        )
    met = report["thresholds_met"]
    print(
        f"  verdict_accuracy={_fmt_pct(s['verdict_accuracy'])} "
        f"(>=80%? {met['verdict_accuracy']})"
    )
    print(f"  fnr_mal={_fmt_pct(s['fnr_mal'])} (<=10%? {met['fnr_mal']})")
    print(
        f"  ttp_coverage(exact)={_fmt_pct(s['ttp_coverage'])} "
        f"(>=60%? {met['ttp_coverage']}); family={_fmt_pct(s['ttp_coverage_family'])}"
    )
    print(f"  fpr={_fmt_pct(s['fpr'])} (<=20%? {met['fpr']}) basis={report['false_positive_basis']['eligible_cases']}")
    print("\n== Specificity gate (reported separately) ==")
    for g in report["specificity_gate"]:
        print(
            f"  {g['case_id']}: agent={g['agent_verdict']} expected={g['expected_verdict']} "
            f"-> {'PASS' if g['passed'] else 'FAIL'} (over-called MALICE? {g['over_called_malice']})"
        )
    sec = report["secondary_metrics"]
    print("\n== Secondary ==")
    print(f"  ioc_recall (aggregate) = {_fmt_pct(sec['ioc_recall']['aggregate_recall'])}")
    print(f"  peirce_alignment = {sec['peirce_alignment']} (not deterministically scorable)")
    print(f"  abstention_rate = {_fmt_pct(sec['abstention_rate'])}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score vigia-cases agent verdicts.")
    ap.add_argument("--results", required=True, type=Path, help="dir of *.verdict.json")
    ap.add_argument("--truth", required=True, type=Path, help="dir of <case>/ground_truth.json")
    ap.add_argument("--out", required=True, type=Path, help="output report JSON path")
    ap.add_argument("--date", required=True, help="evaluation date (YYYY-MM-DD)")
    ap.add_argument("--agent-id", default="neo-finds-evil", help="agent identifier")
    args = ap.parse_args(argv)

    report = score_benchmark(args.results, args.truth, args.agent_id, args.date)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print_summary(report)
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
