# Accuracy Report

This report is a deliberately **honest** self-assessment of the agent + correlation layer on the SRL-2018 case. It follows the reliability framing of recognized DFIR-LLM evaluation work (e.g. **DFIR-Metric**, which scores not just raw accuracy but **reliability** — explicitly rewarding a model that **abstains when uncertain** over one that gives a confident wrong answer). Throughout, we distinguish **confirmed** findings (direct, reproducible evidence) from **inferences** (name/timing/behavioral heuristics), and we document **errors the agent caught and corrected** rather than hiding them.

The design intent: the tools make it *easy to abstain correctly*. Hunts return typed, bounded results; `get_event` forces a finding back to a source artifact; and where evidence is missing, the honest output is "attempted / unconfirmed," not a fabricated confirmation.

---

## 1. Confirmed vs. inferred — the SAM-theft call

**Finding:** an attempt to copy the domain controller's **SAM hive out of a Volume Shadow Copy** (`\\BASE-DC\C$\@GMT-2018.08.31-11.00.01\…\config\SAM`), issued from `SRL-FILE`.

**What is confirmed:** the command was **compiled and run by the PowerShell engine** on `SRL-FILE` at 2018-08-31 22:52:08 UTC — proven by the *decoded* script-block content (EID 4104). That much is direct evidence.

**What is NOT confirmed — and is reported as such:** that the copy **succeeded** (snapshot actually present + share reachable in user context + bytes written). The agent ran an explicit corroboration check and abstained from "confirmed" because:
- **No process-execution event** — *and none is expected*: `cp` is the PowerShell `Copy-Item` alias, runs in-process inside the already-running agent, spawns no child, so there is no 4688/EID 1 to find. Absence here is **not** exculpatory (we say so rather than over-reading the silence).
- **No file-creation telemetry** — `SRL-FILE` has no Sysmon, so no EID 11 confirms the hive landed locally.
- **No time-anchored share access** — the DC's 4624 set was de-duplicated to `(user, src-IP, logon-type)` tuples with no per-event timestamps, so a user-context C$ access *at 22:52* can be neither confirmed nor refuted; EID 5140/5145 are not in the graph.

**Call: "ATTEMPTED DC credential theft," not "confirmed."** This is the model abstaining on the *success* claim while still reporting the *attempt* with HIGH confidence — exactly the reliability behavior DFIR-Metric rewards. Contrast with the same-case `PWDumpX.exe` on `SRL-DMZFTP`, which **is** rated confirmed/executed because a 4688 records it running with a full path from the attacker's own staging directory.

---

## 2. Error caught and corrected — the `SRL-FILE` persistence mis-attribution (F1)

**The error (first draft):** the agent initially listed `SRL-FILE` as a **fourth** host running the WMI `PerformanceMonitor` / `Install-Persistence` fileless persistence (alongside RD01/RD02/WKSTN05).

**Root cause:** a **string conflation**. `SRL-FILE`'s only `perfmon` references are the attacker's **staging directory** `C:\Windows\Temp\perfmon\` and the `n.ps1` payload path (the C2 stager). The substring "perfmon" / "PerformanceMonitor" was conflated with the **persistence `__EventFilter` name** `PerformanceMonitor` — two different things that share a string.

**How it was caught — re-verification against raw artifacts with positive controls.** The agent re-checked `SRL-FILE`'s **raw** extracted EVTX (not the graph projection) for the persistence signatures and found **0** occurrences of `install-persistence` / `performancemonitor` / `systemperformancemonitor` / `eventfilter` / `eventconsumer`, and **0** WMI-Activity EID 5861 — while the **positive controls** (RD01/RD02/WKSTN05) hit in *both* raw and graph. A real signal hits both representations; a string artifact does not.

**The correction:** persistence stands on **three** hosts (RD01/RD02/WKSTN05); `SRL-FILE` was used for the SAM grab (§1), **not** for persistence. The fix is recorded inline in the findings, not silently overwritten.

**Why it matters for scoring:** this is self-correction operating on *findings*, not just on tool-call errors — the agent disproved its own earlier claim by designing a raw-vs-graph control test. Traceability (`get_event` → source `.evtx`) is what made the raw cross-check possible.

---

## 3. Error caught and corrected — the empty-hunt projection gap (0 → 26,372 Sysmon-projected SPAWNED)

**The error (first draft):** several relationship-based hunts (`sysmon_process_spawn`, `external_connections`, `lateral_logons`, `registry_persistence`, `sysmon_file_touch`) returned **0 rows**, because the ingest had **not** projected the rich Sysmon EID 1/3/11/12/13 + 4624 events into graph *relationships* — every `SPAWNED` edge then carried `source:'vol_pslist'` (596 such edges) and the Sysmon spawn hunt was empty. The first findings were therefore built by sweeping `WindowsEvent.commandLine` / `scriptBlock` text directly.

**How it was caught:** an empty hunt over a graph that obviously *should* contain spawn data is a red flag, not a "no evil here" — the agent treated 0 rows as a coverage bug to investigate, not a finding.

**The correction:** a graph rebuild added five projections. `SPAWNED{source:'sysmon'}` went from **0 → 26,372** (verified live), and `CONNECTED_TO` (936), `LOGGED_IN` (392), `MODIFIED` (7,685), `CREATED_FILE` (19,109) appeared. Total `SPAWNED` across all sources is therefore **26,968** (26,372 Sysmon-projected + 596 pslist-derived). The previously-empty hunts now return data and **corroborate** the text-swept findings (e.g. `powershell.exe → csc.exe/cmd.exe/reg.exe` spawn chains on WKSTN05; the proxy `172.16.4.10` as the top `CONNECTED_TO` destination). The original conclusions were unchanged — the projection added corroboration, it didn't overturn attribution.

**Lesson encoded in the tooling:** an empty `run_hunt` result is reported plainly (`row_count: 0`) so the agent can distinguish "no evidence" from "no coverage" instead of mistaking a projection gap for an all-clear.

---

## 4. Known limitation — EID 10 (Sysmon ProcessAccess) is contentless

`SRL-WKSTN05` holds 5,774 EID 10 (ProcessAccess) events — the natural place to confirm **LSASS-targeting credential access**. But `SourceImage` / `TargetImage` / `GrantedAccess` / `CallTrace` were **not** parsed into node properties this load; every standard field is empty. **We therefore cannot confirm LSASS credential access from the graph**, and we say so — the determination would need the raw `Microsoft-Windows-Sysmon%4Operational.evtx`. (Credential theft is still established independently via §1 and `PWDumpX`.) This is an abstention forced by a parsing gap, reported rather than papered over.

Related, narrower gaps reported in the findings: 7045 service **binary paths** (`imagePath`) weren't parsed (so Metasploit/masquerading service identification rests on **name + timing**, an explicit *inference*, rated MEDIUM); and the C2 domain `squirreldirectory.com` does **not** appear in DNS telemetry (no Sysmon on the Empire hosts) — it's identified from decoded 4104 content, which is noted as *stronger* than a DNS lookup, not weaker.

---

## 5. Known false-positive direction — the `query_graph` lexical guard over-rejects

The `query_graph` write-rejection pre-check is **intentionally biased toward false positives**: a benign read query that contains a write *keyword* as a substring or identifier (e.g. a property literally named `created`, or the token `set` inside a longer word the whole-word check still flags in edge cases) can be **refused** even though it only reads.

The most consequential case for an analyst: because the check scans **string literals** too (that is what catches write verbs smuggled into apoc procedure arguments), a legitimate search for **anti-forensics command lines is rejected** — e.g. `MATCH (p:Process) WHERE p.commandLine CONTAINS 'vssadmin delete shadows' RETURN p`, or literals containing `reg delete` / `Set-MpPreference`, are refused on the `DELETE`/`SET` tokens. The workaround is the constrained surface that bypasses the lexical guard by design: named hunts (`run_hunt`, e.g. `log_cleared`, `powershell_script`) and `get_event` traceback. This trade-off is deliberate and disclosed (also in the README's Known-limitations list), not an accident.

**Why we accept that direction:** for a read-only forensic server, **over-rejection is the safe failure mode** — it can only block a query, never allow a write. And it is **backstopped**: the real guarantee is the Neo4j **READ transaction** (`default_access_mode=READ`), which rejects writes regardless of text, so the lexical guard is defense-in-depth, not the boundary. A 21-case bypass battery (`tests/test_mcp_server.py`) confirms no *write* slips through; the cost is the occasional false rejection of a read, which surfaces as a typed `write_rejected` error the agent can rephrase around.

We also report the **benign-activity exclusions** the agent made on this case (to avoid false-positive *findings*): F-Response/`mnemosyne` IR tooling, defensive Sysmon-deployment download cradles on DMZFTP, `wevtutil im` Office manifest installs (not log clearing), and Chrome NXDOMAIN-probe random DNS (not DGA). Each was explicitly classified as **not attacker activity** rather than counted as evil.

---

## Summary

| Item | Status | Confidence |
|---|---|---|
| Brute force against `SRL-DMZFTP` (20,531 × 4625) | **Confirmed** | HIGH |
| PowerShell Empire C2 (`squirreldirectory.com`) | **Confirmed** (decoded 4104) | HIGH |
| WMI `PerformanceMonitor` persistence (RD01/RD02/WKSTN05) | **Confirmed loaded/compiled**; instantiation **inferred** | HIGH / MEDIUM-HIGH |
| `SRL-FILE` as a persistence host | **Retracted** (caught via raw-vs-graph control) | — |
| `PWDumpX.exe` on DMZFTP | **Confirmed executed** | HIGH |
| DC SAM-from-VSS copy | **Attempted** (command ran); success **abstained** | HIGH attempt / unconfirmed success |
| Metasploit identity of `df0398a`/`8556ce1` | **Inferred** (name + timing; binary path not parsed) | MEDIUM |
| LSASS credential access via EID 10 | **Abstained** (fields not parsed) | — |
| April–May 2018 cluster = the intrusion | **Abstained / likely baseline** | LOW that it's the intrusion |

The throughline: **report what the evidence supports, label inferences as inferences, abstain when a claim can't be corroborated, and correct earlier errors in the open.**

---

## 6. Benchmark: vigia-cases (verdict reasoning over curated artifacts)

This section reports a **separate, complementary** evaluation against an external,
community-standard dataset: **`vigia-cases`** by Anna Tchijova, the DFIR benchmark
the hackathon organiser pointed teams at as a scoring template. It measures the
agent's **forensic-intent adjudication** — given a curated artifact list, emit a
verdict (`MALICE` / `SUSPICION` / `BENIGN` / `ABSTAIN`), confidence, MITRE ATT&CK
TTPs, and IOCs — scored against the dataset's canonical `ground_truth.json` using
the metrics and thresholds in its `SCORING_GUIDE.md`.

### Scope — what this does and does not measure

This benchmark exercises **verdict reasoning over Anna's hand-curated artifact
descriptors** (small self-contained JSON). It does **not** use our Neo4j
correlation graph or the `forensics-graph` MCP server at all, and it is **not** a
measure of cross-host / raw-scale evidence correlation — that capability is the
subject of §§1–5 above and the `architecture.md` / `protocol-sift-integration.md`
docs. The two are evaluations of **different layers** of the same pipeline
(*correlation over raw evidence* vs. *intent adjudication over curated findings*);
**neither validates the other**, and we do not claim it does.

### Methodology — isolation and reproducibility

The dataset stores each case's answer (`ground_truth.json`) in the same directory
as the agent input (`case.json`). The benchmark is only meaningful if the agent
never sees the answer, so:

- **Input isolation.** Only the four `case.json` files were copied into an
  eval-only working tree (`~/vigia-eval/inputs/`, outside this repo). The check
  `find ~/vigia-eval/inputs -name 'ground_truth*' -o -name 'manifest*' -o -name
  'index*'` returns **nothing** — no answer file exists anywhere the agent can reach.
- **Fresh, blind context per case.** Each verdict was produced by an independent
  agent context pointed at **exactly one** `case.json` and forbidden from reading
  any other file (no ground truth; no cross-case contamination).
- **Deterministic, committed scorer.** `tools/vigia_score.py` (unit tests in
  `tests/test_vigia_score.py`, 10 passing) reads ground truth **only** at scoring
  time and emits the report JSON. Same inputs → byte-identical report.
- **Archived outputs.** The raw per-case verdicts and the full report JSON are in
  [`docs/benchmark/`](benchmark/). We do **not** vendor any `vigia-cases` content
  (it is Anna's separately-licensed dataset — see Attribution); only our own
  verdicts and scorer are committed.

### (a) Headline accuracy — `score_against` tier (VIGIA-REAL-001 / 002 / 007)

Only the `score_against` tier is valid for accuracy claims (per `SCORING_GUIDE.md`).
All three carry ground-truth verdict **MALICE**.

| Case | Incident | Our verdict | Truth | ✓ | Conf | TTP (exact) | TTP (family) | IOC recall |
|---|---|---|---|---|---|---|---|---|
| VIGIA-REAL-001 | NIST Hacking Case (war-driving / credential theft) | MALICE | MALICE | ✅ | 0.95 | 1/6 (16.7%) | 1/6 (16.7%) | 4/10 |
| VIGIA-REAL-002 | NIST Data Leakage (insider exfiltration) | MALICE | MALICE | ✅ | 0.95 | 1/5 (20.0%) | 3/5 (60.0%) | 5/5 |
| VIGIA-REAL-007 | Nitroba harassment (network attribution) | MALICE | MALICE | ✅ | 0.93 | 0/3 (0.0%) | 2/3 (66.7%) | 3/3 |

Report-JSON summary (full file: [`docs/benchmark/vigia-report.json`](benchmark/vigia-report.json)):

```json
{
  "tier": "score_against",
  "cases_evaluated": 3,
  "summary": {
    "verdict_accuracy": 1.0,
    "fpr": 0.0,
    "fnr_mal": 0.0,
    "ttp_coverage": 0.143,
    "ttp_coverage_family": 0.429
  }
}
```

| Metric | Result | Threshold | Met? |
|---|---|---|---|
| Verdict Accuracy | **100%** (3/3) | ≥ 80% | ✅ |
| FPR (false-positive rate) | **0%** | ≤ 20% | ✅ |
| FNR-MAL (MALICE → BENIGN) | **0%** | ≤ 10% | ✅ |
| TTP Coverage (exact) | **14.3%** (2/14) | ≥ 60% | ❌ |
| TTP Coverage (family, parent-matched) | 42.9% (6/14) | — (informational) | ❌ |

> **Statistical-power caveat (read before citing the headline).** These
> numbers rest on very small n: verdict accuracy is computed over **3**
> `score_against` cases (achievable values: 0/33/67/100% — the ≥80% bar can
> only be met by a perfect 3/3), and the FPR over a **single** FP-eligible
> case (mechanically 0% or 100%, no resolution between). The scorer itself
> discloses this basis in its output (`false_positive_basis`); we foreground
> it here so "100% / 0%" is read as *consistent with* good adjudication on
> this dataset, not as a precision claim.

**The verdicts are correct; the TTP labelling is the honest weak spot — we do not
paper over it.** Two distinct effects drive the low coverage:

1. **Granularity mismatch.** The agent emitted *parent* techniques where the
   dataset's canonical set uses *sub-techniques* — e.g. on 007 it produced `T1566`
   (canonical `T1566.001`) and `T1585.002` (canonical `T1585.001`). Exact matching
   scores these as misses; *family* matching (parent-technique level) recovers
   them, which is why 002/007 jump to 60–67% under the lenient view.
2. **Genuinely different technique selection.** On 001 the agent framed the case
   around credential interception (`T1557`, `T1539`, `T1592.001`) while the canonical
   set emphasises discovery/scanning/input-capture/unsecured-credentials (`T1018`,
   `T1056`, `T1552`, `T1595`). Both are defensible readings of the same artifacts,
   but they pick different ATT&CK IDs — so even family matching only recovers 1/6.

We report **exact coverage as the headline** because it mirrors `SCORING_GUIDE.md`'s
own worked example; family coverage is shown for transparency, not to inflate the
number. The takeaway: the agent's *adjudication* is reliable, its *canonical-TTP
alignment* is not — and it misses the dataset's ≥60% bar on both views.

IOC recall was 12/18 (66.7%) aggregate. The misses are concentrated in 001, where
the agent recovered the email/hash/hostname IOCs but not several
registry/config-path/SID artifacts (`...\mirc.ini`, the Mr. Evil SID, a secondary
IP/MAC) — consistent with reasoning from the incident narrative rather than
enumerating every low-level identifier.

### (b) Specificity gate — VIGIA-REAL-005 (reported separately, NOT in the headline)

`VIGIA-REAL-005` ("Encrypt Them All", `build_and_test` tier) is the dataset's
**intentional false-positive gate**. Its ground truth is **SUSPICION**, not MALICE:
multiple encryption layers can be legitimate personal security. Per the guide, an
agent **passes only by emitting SUSPICION** (or abstaining appropriately) and
**fails automatically by over-calling MALICE** — no partial credit. It is reported
here in isolation and is **never folded into the headline accuracy number**.

| Case | Our verdict | Truth | Result | Over-called MALICE? | Conf |
|---|---|---|---|---|---|
| VIGIA-REAL-005 | **SUSPICION** | SUSPICION | ✅ **PASS** | No | 0.60 |

The agent saw the concealment signals (AES + BitLocker + GPG layering, a BitLocker
volume named "R2D2") and explicitly weighed the **null hypothesis** — *"a
privacy- and security-conscious user employing entirely standard, lawful encryption
tools"* — then **declined to escalate to MALICE** because no artifact revealed the
encrypted content, a counterparty, malware, or any unauthorized act. It marked the
"communication with an external party" and "content is illicit" claims **INFERRED,
not CONFIRMED**.

**This is the same discipline as the SAM-theft call in §1.** There, the agent
reported the credential-theft *attempt* at HIGH confidence but **abstained on the
success claim** for want of corroboration ("ATTEMPTED, not confirmed"). Here, it
reports *suspicion* of concealment but **declines the malice claim** for want of
content, counterparty, or victim. In both cases the agent refuses to convert an
anomaly into a confirmed accusation — which is exactly the reliability behaviour
(abstain/under-claim when uncertain) that the dataset's gate, and DFIR-Metric,
reward over a confident wrong answer.

### Training-data caveat (stated plainly, per the organiser's instruction)

These are **published** forensic cases. The two NIST cases especially —
**VIGIA-REAL-001** (NIST Hacking Case) and **VIGIA-REAL-002** (NIST Data Leakage) —
are among the most heavily documented DFIR exercises on the public internet, with
full walkthroughs and answer keys widely mirrored; VIGIA-REAL-007 (Nitroba) and
VIGIA-REAL-005 (Ali Hadi "Encrypt Them All") are likewise public challenges. A
language model may therefore **recall** the documented answer rather than **reason**
to it from the artifacts, and **we cannot distinguish the two from the output**. We
state this rather than present the score as evidence of pure reasoning.

The **same caveat applies to our own SRL-2018 work**: SRL-2018 / SHIELDBASE is the
SANS **FOR508** scenario, which is also documented online. Wherever this report
cites SRL-2018 results, the recall-vs-reason caveat holds there too.

### Attribution

This benchmark uses the **`vigia-cases`** dataset by **Anna Tchijova**, used under
its **Apache-2.0** license. Cloned commit **`5453805`**.

```
Tchijova, A. (2026). vigia-cases: DFIR Benchmark Dataset for Forensic Intent
Analysis. SANS FIND EVIL Hackathon 2026. https://github.com/annatchijova/vigia-cases
```

*Integrity note (returned upstream as friendly feedback):* `sha256sum --check
hashes.sha256` on the cloned dataset verifies **all** case and ground-truth files;
only `README.md` mismatches — a stale hash after a post-generation edit to the
file. Benign, but worth flagging to the author for an integrity-focused benchmark.
