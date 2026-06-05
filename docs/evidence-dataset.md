# Evidence Dataset Documentation

## What the agent was tested against

The correlation graph holds the **SRL-2018 / SHIELDBASE** enterprise-intrusion case — the **SANS FOR508** lab scenario ("Stark Research Labs", domain `SHIELDBASE.LAN`). It is a **7-host Windows enterprise** with both **disk and memory** evidence:

| Host | Role | Evidence |
|---|---|---|
| `SRL-DC` | Domain controller | disk + memory |
| `SRL-RD01` | Remote-desktop / app server | disk + memory |
| `SRL-RD02` | Remote-desktop / app server | disk + memory |
| `SRL-FILE` | File server | disk + memory |
| `SRL-WKSTN01` | Workstation (has Sysmon) | disk + memory |
| `SRL-WKSTN05` | Workstation (has Sysmon) | disk + memory |
| `SRL-DMZFTP` | Internet-facing DMZ FTP host | disk only (no memory image) |

**Artifact types ingested** (Phase-1 loaders, `src/forensics/ingest/loaders/`): Windows event logs (EVTX — Security 4624/4625/4688/4104, System 7045/104, Sysmon 1/3/11/12/13/22), Volatility memory artifacts (psscan/pslist/netscan/dlllist), shimcache, prefetch, MFT / path catalog, registry, and bulk_extractor output. Ingest tiers **triage + execution** are loaded for all 7 hosts.

## Source / provenance

The scenario is the **publicly published SANS FOR508 training case** — the *same* case that Protocol SIFT ships as its own demo (Stark Research Labs / SHIELDBASE, with responder accounts `rsydow` / `cbarton`). That overlap is deliberate and useful: this project's correlation layer is a **drop-in second opinion over Protocol SIFT's own demo data**, so a judge can watch Protocol SIFT analyze one host per-artifact while these MCP tools answer "what else touched that host across the other six."

**Everything in the graph is a training-scenario artifact** — host names, account names (`spsql`, `rsydow`, `nfury`, …), IP addresses (`172.16.x.x`, `10.10.x.x`), and indicators (`squirreldirectory.com`, etc.) are all part of the published FOR508 scenario. **No real persons or real infrastructure are represented.**

## How evidence becomes a graph (out-of-band extraction pipeline)

The graph judges restore is the output of a **Phase-1 extraction + ingest pipeline** (`src/forensics/ingest/`, console script `forensics-ingest`). It is documented here for depth, but it **runs out-of-band and is NOT part of the judge runbook** — judges restore the pre-built graph release asset and never run extraction. The pipeline:

1. **Acquire / mount** the disk and memory images per host, read-only.
2. **Extract** artifacts with standard DFIR tooling — **Plaso** (`log2timeline`/`psort`) for the EVTX super-timeline; **Volatility 3** (`psscan`/`pslist`/`netscan`/`dlllist`) for memory; plus shimcache, prefetch, MFT/path-catalog, registry, and `bulk_extractor` — emitting **normalized JSONL** per artifact type.
3. **Ingest** the JSONL into Neo4j through per-artifact loaders, applying **load-time de-duplication** (e.g. high-volume 4624 logons collapse to unique `(user, ip, logonType)` tuples; Sysmon EID 3 connections to unique `(image, dstIP, dstPort)` tuples) so every *unique fact* is preserved without raw-event bloat.
4. **Project relationships** as a post-ingest pass — `SPAWNED`, `CONNECTED_TO`, `LOGGED_IN` (with `logonType`+`ip`), `MODIFIED`, `CREATED_FILE`/`DELETED_FILE` — turning flat events into the cross-host, cross-time graph the MCP tools query.

Crucially, **the agent has no tool that runs any of this** — graph construction is entirely out-of-band, which keeps the write path out of the agent (an architectural guardrail; see `architecture.md`). The agent only ever *reads* the finished graph.

## Graph scale

Measured live against the restored graph (read-only counts). **~359,788 nodes / ~1.9M edges.**

**Nodes by label**

| Label | Count |
|---|---:|
| `WindowsEvent` | 300,435 |
| `Process` | 27,739 |
| `File` | 19,564 |
| `ScriptBlock` | 6,223 |
| `RegistryKey` | 4,566 |
| `IPAddress` | 708 |
| `WindowsService` | 275 |
| `UserAccount` | 192 |
| `Domain` | 79 |
| `Host` | 7 |
| **Total** | **359,788** |

**Edges by type**

| Relationship | Count |
|---|---:|
| `DESCRIBES` | 1,449,798 |
| `REPORTED` (event → host) | 300,435 |
| `MODIFIED_REGISTRY` | 62,988 |
| `RAN_ON` (process → host) | 27,739 |
| `SPAWNED` (parent → child process) | 26,968 † |
| `CREATED_FILE` | 19,109 |
| `MODIFIED` | 7,685 |
| `LOADED_MODULE` | 6,872 |
| `EXECUTED_SCRIPT` | 6,223 |
| `EXECUTED` | 3,281 |
| `RESOLVED_DNS` | 2,278 |
| `CONNECTED_TO` | 936 |
| `LOGGED_IN` (with `logonType` + `ip`) | 392 |
| `INSTALLED_SERVICE` | 338 |
| **Total** | **~1,915,042** |

† `SPAWNED` = **26,372** Sysmon-projected (`source:'sysmon'`) + **596** pslist-derived (`source:'vol_pslist'`). The 26,372 figure is the one referenced in `accuracy-report.md` §3 (the projection that took the Sysmon spawn hunt from 0 rows to populated).

> **Timestamp note.** `WindowsEvent.timestamp` is stored as the string repr of a Python `Filetime` object (e.g. `{… 'timestamp': 131808278432280264}`); times are derived by extracting the integer and converting FILETIME→UTC (`epochSeconds = ftInt/10_000_000 − 11_644_473_600`). This is a known dataset quirk, documented because it affects how time-window queries are written.

## What the agent found (headline)

A **hands-on-keyboard intrusion** across `SHIELDBASE.LAN`, running **2018-08-28 → 2018-09-07** and peaking **2018-08-31**, operating a **PowerShell Empire**-style toolkit. The cross-host chain the graph makes visible:

- **Initial access (probable):** a month-long **brute-force campaign against `SRL-DMZFTP`** — 20,531 × EID 4625 (2018-08-02 → 09-07), targeting accounts including `spsql`, `rsydow`, `nfury`, `administrator`. *Cross-host correlation showed the internal source IP `172.16.4.5` is the file server itself acting as a pivot — i.e. an internal host was already compromised, which reframes DMZ-FTP as plausibly a lateral target. (See `accuracy-report.md`.)*
- **C2:** external domain **`squirreldirectory.com`** (`/a` Empire stager, `/download/n.ps1` secondary payload) executed via in-memory `IEX … DownloadString(...)` cradles staging from a loopback listener — visible across `SRL-RD01`, `SRL-RD02`, `SRL-WKSTN05`, `SRL-FILE` in **decoded** PowerShell script blocks (EID 4104).
- **Fileless persistence:** WMI `__EventFilter`→`CommandLineEventConsumer` persistence named **`PerformanceMonitor` / `SystemPerformanceMonitor`**, on RD01/RD02/WKSTN05.
- **Credential theft:** **`PWDumpX.exe`** executed on `SRL-DMZFTP`; and an **attempted** DC **SAM-hive copy from a Volume Shadow Copy** issued from `SRL-FILE` — command provably executed in PowerShell, copy *success* not independently corroborated (the confirmed-vs-inferred distinction is the centerpiece of `accuracy-report.md`).
- **Lateral movement:** **PsExec** (`-i -s powershell.exe`, SYSTEM) and **service-based execution** — random-hex Metasploit-style services (`df0398a`, `8556ce1`) on `SRL-RD02`, `PSEXESVC` on `SRL-DMZFTP`.

A separate **April–May 2018** cluster of masquerading/`LARIAT` services + log-clears **predates the intrusion by ~3 months** and is flagged as likely **lab/baseline/simulation** infrastructure, not the incident — documented to prevent false-positive attribution.

This is precisely the kind of **cross-host, cross-time** reasoning that no single per-artifact tool output can express, and it is the analytical-reasoning demonstration for the submission. The honest accuracy self-assessment — confirmed findings, inferences, and **errors caught and corrected** — is in **`accuracy-report.md`**.
