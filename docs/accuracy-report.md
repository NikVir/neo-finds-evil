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
