# Protocol SIFT: Recon & Integration Plan

**Status:** recon + planning only. No code changes to sans-find-evil yet. No system-wide install performed (see §0).
**Author:** generated 2026-06-05 for the SANS "FIND EVIL!" hackathon (findevil.devpost.com, deadline June 15).
**Source inspected:** `github.com/teamdfir/protocol-sift` @ `main` (cloned read-only to `/tmp/protocol-sift`).

---

## 0. TL;DR + install decision

**What Protocol SIFT actually is:** a **Claude Code configuration bundle** for the SANS SIFT Workstation, authored by Rob Lee (SANS / teamdfir). It is **not** an MCP server, has **no database, no graph, and no cross-host correlation**. "Connecting AI agents to forensic tools" is achieved purely by (a) a global `settings.json` that pre-approves ~80 forensic CLIs for the `Bash` tool, and (b) five **Skills** (prompt playbooks) that tell the agent how to drive Volatility 3 / Plaso / Sleuth Kit / EZ Tools / YARA. Everything installs into `~/.claude/`.

**Install decision: did NOT run the official installer against our machine.** Step 1 inspection showed `install.sh` **overwrites our global Claude Code config**: it copies the repo's `global/{CLAUDE.md,settings.json,settings.local.json}` over `~/.claude/` (it backs them up to `.bak-<ts>` first, lines 81–91 of `install.sh`). That is a hard conflict with our setup (our permissions, hooks, and memory live in `~/.claude/`), and SIFT's `settings.json` would also block `curl`/`wget`/`WebFetch` and scope all writes to `./analysis|reports|exports`, breaking our dev workflow. Per the task's "STOP if it touches our Claude Code config" rule, I instead:
- cloned the repo read-only and inspected every file, and
- ran the installer **sandboxed** under `HOME=/tmp/sift-home`, it succeeded cleanly (exit 0), proving the entire "install" is just file copies into `~/.claude` with **no MCP registration, no services, no changes outside `~/.claude`**.

**No conflict** with our `neo4j-forensics` container, our `.venv`, or our repo files. SIFT touches none of them (it has no database and writes only to `~/.claude`). The only conflict is the global-config overwrite, which the sandbox avoided.

**Surprising alignment:** Protocol SIFT's shipped demo case **is the SRL / SHIELDBASE FOR508 scenario**: Stark Research Labs, CRIMSON OSPREY APT, `rd01` as primary compromise host, responders **Roger Sydow** and **Clint Barton** (= our `rsydow` / `cbarton`). That is the *exact* evidence our Neo4j graph already ingested and correlated (case `srl-2018`). Our correlation layer is a drop-in second opinion over SIFT's own demo data.

---

## 1. Plain-language summary (for README / Devpost)

> **Protocol SIFT** is SANS's proof-of-concept for autonomous DFIR: it turns a stock SANS SIFT Workstation into an AI-driven forensics operator by configuring Claude Code with (1) a DFIR "system prompt" that sets a strict read-only, court-defensible operating posture, (2) a permission policy that pre-authorizes the SIFT toolset so the agent can run Volatility, Plaso, Sleuth Kit, EZ Tools, and YARA without pausing, and (3) skill files that encode expert CLI usage for each tool. The agent investigates **one artifact / one tool at a time** (dump a process, parse an event log, build a timeline) and writes findings to a per-case directory. It is brilliant at *depth on a single artifact* but has **no memory across hosts or artifacts**: each tool invocation is an island.

**sans-find-evil adds the missing layer:** a Neo4j **correlation graph** of every artifact across every host and the whole timeline, exposed to the *same* agent as read-only query/hunt tools, so the agent can reason **across hosts and across time** (lateral movement, cross-host tool reuse, credential-theft chains), not just within one tool's output.

---

## 2. Architecture map (Step 3 findings, with paths)

### 2.1 Components (repo: `teamdfir/protocol-sift`)

| Path | Installs to | What it is |
|---|---|---|
| `install.sh` | — | Bash installer; copies files into `~/.claude/`, optionally installs Claude Code + WeasyPrint. **No MCP, no service, no DB.** |
| `global/CLAUDE.md` | `~/.claude/CLAUDE.md` | Global system prompt: role = "Principal DFIR Orchestrator", strict read-only evidence rules, **fully-autonomous (never ask) mode**, installed-tool-paths table, a tool→skill routing table, and a **self-correction directive** ("On failure: read stderr → hypothesize → correct → retry"). |
| `global/settings.json` | `~/.claude/settings.json` | Claude Code **permission policy** (see §2.3) + a `Stop` hook that appends a chain-of-custody line to `./analysis/forensic_audit.log`. |
| `global/settings.local.json` | `~/.claude/settings.local.json` | Machine-local allows (`sudo apt`, `psort.py`). |
| `skills/memory-analysis/SKILL.md` | `~/.claude/skills/...` | Volatility 3 (`/opt/volatility3-2.20.0/vol.py`) + Memory Baseliner playbook. |
| `skills/plaso-timeline/SKILL.md` | " | `log2timeline.py` / `psort.py` / `pinfo.py` super-timeline playbook. |
| `skills/sleuthkit/SKILL.md` | " | TSK (`fls`/`icat`/`mmls`/`mactime`/`tsk_recover`) + `ewfmount` offsets. |
| `skills/windows-artifacts/SKILL.md` | " | EZ Tools (`EvtxECmd`/`MFTECmd`/`RECmd`/`AmcacheParser`), EVTX, registry. |
| `skills/yara-hunting/SKILL.md` | " | YARA rules / IOC sweeps / bulk scanning. |
| `case-templates/CLAUDE.md` | `~/.claude/case-templates/CLAUDE.md` | Per-case project prompt; ships pre-filled with the **SRL FOR508** scenario. |
| `analysis-scripts/generate_pdf_report.py` | `~/.claude/analysis-scripts/` | WeasyPrint HTML→PDF report generator. |

Skills total ~2,138 lines: substantial, well-written CLI playbooks.

### 2.2 How it's invoked
The user `cd`s into a case dir (`/cases/<CASE>/` with `{analysis,exports,reports}` subdirs and a project `CLAUDE.md`), mounts evidence **read-only** (`ewfmount` → `mount -o ro,loop,offset=…`), and runs `claude`. The global + project CLAUDE.md load automatically; Skills load on demand via the routing table. There is **no server to start**: the "tools" are just shell CLIs the permission policy allows.

### 2.3 Where the security boundary actually is (critical for scoring)
SIFT's guardrails are **prompt + config + OS**, not per-tool architectural:

- **Prompt (CLAUDE.md):** "Never modify files in `/cases/`, `/mnt/`, `/media/`", instruction only.
- **Config (`settings.json` `permissions`):** `allow` includes **`Bash(*)`** (i.e. *any* shell command) plus an explicit forensic-CLI allowlist; `deny` blocks `rm -rf`, `dd`, `wget`, `curl`, `ssh`, `WebFetch`; `Write`/`Edit` are scoped to `./analysis|reports|exports`; `defaultMode: acceptEdits`. So tool **access is unrestricted Bash gated by a denylist**: the harness enforces it, but it is a *list*, not a property of the tools themselves.
- **OS:** evidence integrity ultimately rests on mounting images `-o ro` and a denylist on `dd`/`rm`.

**Implication for the hackathon's "architectural vs prompt-based guardrails" score:** SIFT's evidence-write protection is config/OS-enforced, but its *tool layer* is "run anything via Bash, minus a denylist." There is no layer where a tool *cannot* perform a dangerous action because the action isn't expressible. **That is exactly the gap our MCP layer fills** (§3, §4).

### 2.4 Overlap with what we already built
- **Extraction overlap:** SIFT drives Volatility 3 (psscan/pslist/netscan), Plaso (`log2timeline`/`psort`), TSK, EZ Tools: the same tools our Phase-1 extraction pipeline runs to populate the graph. Difference: SIFT runs them **interactively, per-artifact, per-host**; we run them **batched → normalized → graph**.
- **Correlation overlap: none.** SIFT has zero graph/database/cross-host capability. This is our entire contribution.
- Several SIFT-wrapped CLIs are already present on *this* box (`log2timeline.py`, `fls`, `icat`, `bulk_extractor`, `exiftool`, `foremost`, `strings`, `file`, `md5sum`), so a subset of Protocol SIFT runs here for real; Volatility 3 and `yara` are absent (different install paths). Smoke test (`file`/`md5sum`/`strings` on a throwaway file) passed.

---

## 3. The extension story (how sans-find-evil extends Protocol SIFT)

```
                         Claude Code agent
        (governed by Protocol SIFT global CLAUDE.md rules)
                               │
            ┌──────────────────┴───────────────────┐
            │ (existing: Protocol SIFT)             │ (NEW: our contribution)
            ▼                                       ▼
   Bash + Skills permission layer            Neo4j MCP server  (read-only)
   run volatility / plaso / tsk /            tools: list_hunts, run_hunt,
   EZ Tools / yara — ONE artifact at         query_graph(read-only), 
   a time, on ONE host                       get_host_summary, get_event
            │                                       │
            ▼                                       ▼
   read-only evidence mounts            Neo4j graph: all artifacts × all
   (/mnt/... -o ro)                     hosts × full timeline (our pipeline)
```

**The thesis (refined against what Step 3 found):**
> Protocol SIFT gives the agent **per-artifact tool access**: it can run a forensic tool against a single image and read that one output. Its weakness is that every tool call is an island: no memory across hosts, artifacts, or time. **sans-find-evil adds the correlation layer**: a Neo4j graph of *all* artifacts across *all* hosts (built by our extraction + projection pipeline), exposed to the *same* agent through an **additional, read-only MCP server**. The agent gains hunts and graph queries that reason across hosts and time (lateral movement, cross-host tool reuse, credential-theft chains) which no single SIFT tool output can show.

**What changes the framing (be honest in the write-up):**
1. SIFT is **not** itself MCP-based, so "extends Protocol SIFT" means *we add the MCP layer SIFT lacks and run it alongside SIFT's Skills/permissions*, not "we plug into SIFT's MCP." Our architecture (agent → MCP → [SIFT tools] + [Neo4j tools]) is the **target** state; SIFT today is agent → Bash/Skills. We contribute the MCP correlation server and propose that SIFT's tool access *could* also be MCP-wrapped later.
2. Our second, stronger pitch, **architectural guardrails**: where SIFT's graph-of-evidence would be "Bash + denylist," our Neo4j access is an MCP server that exposes **only read tools** → the agent *cannot* mutate the graph because no write tool exists. That is a genuinely architectural guardrail, and it's exactly the axis the hackathon scores.
3. **Same evidence:** SIFT's demo *is* SRL/SHIELDBASE; our graph already holds the correlated `srl-2018` analysis of it. The demo can show SIFT analyzing `rd01` per-artifact while our MCP tools answer "what else touched `rd01` across the other 6 hosts", a clean, literal extension on identical data.

---

## 4. Build plan: the Neo4j MCP server

A new component (greenfield, our repo has no MCP code today). Python, using the official **`mcp` SDK / FastMCP**, **stdio** transport, registered with Claude Code via `claude mcp add` or a `mcpServers` block in `settings.json` (merged into, not overwriting, SIFT's settings; see §6). Wraps existing code so behavior matches the CLI.

### 4.0 BUILD STATUS: ✅ DELIVERED (v1)

Implemented in **`src/forensics/mcp_server.py`** (console script `forensics-mcp`), registered project-scoped via **`.mcp.json`** at the repo root. `mcp>=1.2` added to `pyproject.toml`. **50 unit tests** (`tests/test_mcp_server.py`), full suite **173 passed, 5 skipped** (the two live READ-backstop regression tests skip cleanly when no graph is reachable), ruff clean. Read-only verified by a live stdio smoke test (graph byte-identical: 359,788 nodes before and after).

**Final tools (exactly five, all read-only):**

| Tool | Signature | Returns |
|---|---|---|
| `list_hunts` | `() ->` | `[{name, category, description}]` for all 31 hunts (categories overlaid on `hunt.py:QUERIES`). |
| `run_hunt` | `(name: str, limit: int = 100) ->` | `{hunt, rows, row_count, truncated, duration_ms}`. Validates `name`; rejects case-param hunts; read-tx + server timeout; rows capped. |
| `get_host_summary` | `(hostname: str) ->` | `{hostname, total_events, process_count, events_by_event_id[], relationship_counts{spawned_sysmon,connected_to,modified_registry,created_file,logged_in}}`. Validates host exists (else lists hosts). |
| `get_event` | `(event_id: str) ->` | `{event_id, event{…all props…, host}}`, **traceability primitive**. Id scheme is `<HOSTNAME>:<record_number>` (e.g. `SRL-DC:2952977`). |
| `query_graph` | `(cypher: str, params=None, limit_enforced: int = 100) ->` | `{rows, row_count, truncated, limit_applied}` or a typed error. Guarded escape hatch (§4.2). |

**Enforcement implemented:** `query_graph` runs via a new `Neo4jClient.read_query()` that opens the session with `default_access_mode=READ` and an explicit `begin_transaction(timeout=stats_query_timeout())`. Writes are rejected by the **server** regardless of text. On top of that, a lexical `reject_write()` pre-check (comment-stripped, whole-word) blocks `CREATE/MERGE/DELETE/SET/REMOVE/DROP/DETACH/FOREACH`, `LOAD CSV`, `CALL {…} IN TRANSACTIONS`, and apoc/db write procedures. `enforce_limit()` appends `LIMIT 100` when absent and rows are capped in Python regardless. The bypass battery (`test_query_graph_write_rejection_bypass_battery`, 21 cases incl. lowercase/mixed-case/comment-hidden/after-WITH/UNION/CALL-subquery/apoc) **all reject**.

**Registration (judge-facing):**
```bash
git clone <repo> && cd sans-dfir
uv sync                                   # installs deps incl. mcp
# restore the forensic graph into the neo4j-forensics container (see runbook),
# then either rely on the committed .mcp.json (auto-detected by Claude Code in repo root)
#   — or register explicitly:
claude mcp add --transport stdio forensics-graph -- uv run forensics-mcp
claude            # the agent now has list_hunts / run_hunt / get_host_summary / get_event / query_graph
```
`.mcp.json` sets `command: uv, args: ["run","--quiet","forensics-mcp"]` and the `NEO4J_*` env (local default creds) + `FORENSICS_MCP_AUDIT=investigation/mcp-audit.log`.

**Guardrail evidence: live write-rejection transcript** (smoke test, `query_graph` with `MATCH (n) DETACH DELETE n`):
```json
{
  "error": "write operations are not available on this server: write/DDL keyword 'DETACH' is not permitted. This is a read-only forensic graph — use a MATCH/RETURN query, or call run_hunt() for a vetted query.",
  "error_type": "write_rejected",
  "duration_ms": 0.1
}
```
Audit log line for that same call (`investigation/mcp-audit.log`):
```json
{"ts":"2026-06-05T17:49:58.881304+00:00","tool":"query_graph","args":{"cypher":"MATCH (n) DETACH DELETE n","limit_enforced":100},"duration_ms":0.1,"status":"write_rejected","row_count":null}
```
A real `run_hunt('credential_tooling')` over stdio returned `pwdumpx.exe` on `SRL-DMZFTP` (matches FINDINGS); `get_host_summary('SRL-DC')` returned `total_events=137814, process_count=123, 4688=135581`, exact FINDINGS counts.

### 4.1 Tool list (ALL read-only): as proposed, delivered above

| Tool | Signature | Wraps | Notes |
|---|---|---|---|
| `list_hunts` | `() -> [{name, description, tier}]` | `hunt.py:QUERIES` keys + `hunt_deps.py` | Discoverability; 31 hunts today. |
| `run_hunt` | `(name: str, params?: dict) -> {rows, parameters}` | `hunt.py:run_hunt()` (line 417) | Named, vetted, parameterized queries, the safe default. |
| `query_graph` | `(cypher: str) -> {rows}` | `Neo4jClient.query(timeout=)` (neo4j_client.py:144) | **Write-rejected** (see §4.2), server-side timeout, mandatory `LIMIT`. For ad-hoc reasoning. |
| `get_host_summary` | `(hostname: str) -> {events_by_id, processes, edges, …}` | anchored counts à la `coverage.py` | Per-host orientation; Host-anchored, never stacked OPTIONAL MATCH (per commit cae2671). |
| `get_event` | `(id: str) -> {eventId, channel, timestamp, image, commandLine, scriptBlock, host}` | direct `MATCH (e:WindowsEvent {id})` | **Artifact traceability** (see §5.2), maps a finding back to the source EVTX/artifact. |
| `get_timeline` *(opt)* | `(hostname, start, end) -> [events]` | FILETIME-converted window, anchored + LIMIT | Cross-time reasoning within a host. |

### 4.2 How read-only is ENFORCED: architecturally, in three layers
1. **No write tool exists.** The server registers only the read tools above. The agent has *no* MCP affordance to `CREATE`/`MERGE`/`SET`/`DELETE`. This is the primary, architectural guarantee, the property the hackathon rewards.
2. **`query_graph` rejects writes.** Before execution, reject any statement whose (comment-stripped, lowercased) token stream contains write clauses (`create`, `merge`, `set`, `delete`, `remove`, `drop`, `detach`, `load csv`, `call …` procedures that write, `foreach`); additionally run inside a Neo4j **read transaction** (`session.execute_read`) so the driver itself refuses writes.
3. **Server-side resource bounds.** Wrap every query in `neo4j.Query(text, timeout=…)` using `stats_query_timeout()` (neo4j_client.py:23), the *server* aborts long queries; reuse `query_guarded()` (line 158) so a bad query returns a structured error, never hangs. Enforce a default `LIMIT` and reject unbounded scans. (Defense-in-depth option: a dedicated read-only Neo4j role, limited on Community single-DB, so the tool layer is the real boundary.)

### 4.3 Effort estimate

| Piece | Effort | Notes |
|---|---|---|
| MCP server scaffold (FastMCP, stdio, config resolution from `case.py`) | ~0.5 day | boilerplate + connection mgmt |
| `list_hunts` + `run_hunt` | ~0.5 day | thin wrappers over `run_hunt`; map params for the few parameterized hunts |
| `query_graph` with write-rejection + read-txn + timeout + LIMIT | ~1 day | the security-critical piece; needs tests for write-rejection bypasses |
| `get_host_summary` (anchored counts) | ~0.5 day | reuse coverage.py anchored patterns |
| `get_event` + adding source `id`/`channel` to hunt outputs (traceability) | ~1–1.5 days | touches `hunt.py` returns (see §5.2) |
| Registration + alongside-SIFT settings merge + docs | ~0.5 day | `claude mcp add`, README |
| Tests (write-rejection, timeout, read-only enforcement) | ~1 day | mirror the cae2671 test style |
| **Total** | **~5–6 days** | comfortably within the June 15 window |

---

## 5. Gap analysis vs the hackathon's three required demonstrations

### 5.1 Self-correction: **satisfied**
- SIFT already has a *prompt-level* self-correction directive (CLAUDE.md: "read stderr → hypothesize → correct → retry").
- Our side: every MCP tool returns **typed errors** (`error_type ∈ {unknown_hunt, needs_case, write_rejected, timeout, query_error, unknown_host, not_found, bad_request, …}`) with a *what-to-do-instead* message, e.g. a write rejection says "use a MATCH/RETURN query, or call run_hunt()", and a timeout says "anchor on a Host and add a tighter LIMIT". The agent can correct its call rather than give up. **Done.**

### 5.2 Accuracy validation / artifact traceability: **addressed (v1)**
- **The chain now exists:** `get_event(event_id)` returns the full source `WindowsEvent` (incl. `channel`/`logChannel` = the source EVTX) for any event id; and the per-event hunts now **carry `event_id` + `channel`** in their rows, so: *hunt row → `event_id` → `get_event` → source EVTX/artifact → (the SIFT tool, e.g. EvtxECmd/plaso, that parsed it)*. Id scheme documented: `<HOSTNAME>:<record_number>`.
- **Per-hunt traceability status:**
  - **Per-event, now carry `event_id`+`channel`:** `failed_logons`, `dns_queries`, `log_cleared`, `powershell_script`; `after_hours_logons` already carried `id`.
  - **Aggregate/count hunts** (e.g. `service_install`, `event_coverage`, `summary`, `lateral_tool_reuse`): return host + key (eventId/service/tool) sufficient for a follow-up `get_host_summary`/`query_graph`/`get_event`; not per-event by nature.
  - **Process/file hunts** return `p.id`/`f.path` (their native artifact key).
- **Convergence with SIFT:** the artifact `get_event` points to is exactly what a SIFT tool would parse. Traceability spans **both** layers.

### 5.3 Analytical reasoning (across hosts/time): **our core strength; already satisfied**
- The graph correlates all 7 hosts + the full timeline; SIFT cannot. `run_hunt`/`query_graph` let the agent answer cross-host/cross-time questions (lateral movement, cross-host tool reuse, the Empire→PsExec→SAM chains documented in `investigation/srl-2018/FINDINGS.md`). This is precisely what single-tool SIFT outputs cannot express, and it's the headline of the extension.

---

## 6. Open questions for the team

1. **MCP SDK / transport:** Python `mcp`/FastMCP over **stdio** (simplest for Claude Code local) vs HTTP? Recommend stdio.
2. **Registration alongside SIFT without clobbering:** SIFT *overwrites* `~/.claude/settings.json`. If we adopt SIFT's config for the demo, we must **merge** an `mcpServers` block (and re-add our own permissions) rather than let either overwrite the other. Do we ship a combined `settings.json`, or register the MCP server per-project (`.mcp.json` in the case dir)? Recommend per-project `.mcp.json` so we never fight SIFT's global file.
3. **Read-only DB user:** Neo4j Community is single-DB/single-user. A true read-only role isn't really available, so the *tool layer* is the enforced boundary. Acceptable? (We should still document it as the boundary and test it hard.)
4. **Traceability scope:** add `event_id`+`channel` to *all 31* hunts, or just the incident-relevant subset for the demo? (Suggest: the subset that appears in FINDINGS, then generalize.)
5. **Demo narrative:** run real Protocol SIFT (sandbox or a SIFT VM) on `rd01` per-artifact, then show our MCP tools answering the cross-host question on the same SRL data. Does the team want a side-by-side, or our layer driving SIFT tools via the agent?
6. **Scope boundary:** the MCP server stays *read-only query/correlation*. Extraction/ingest remains our Phase-1 pipeline (not an MCP tool), agreed? (Keeps the write path out of the agent entirely, another architectural-guardrail win.)
7. **Attribution/licensing:** README credits Rob Lee / Protocol SIFT (SANS / teamdfir) explicitly as the framework we extend; confirm wording for the Devpost submission.

---

## Appendix: recon evidence trail

- `install.sh` read in full (`/tmp/sift-install.sh`): copies `global/*` over `~/.claude/{CLAUDE.md,settings.json,settings.local.json}` (backup-then-overwrite), installs 5 skills + case template + PDF script; installs Claude Code only if absent; WeasyPrint optional/skipped when piped. No MCP/service/DB.
- `grep -rniE "mcp|fastmcp|neo4j|graph|cypher|server.py"` across the repo → **0 hits**. Confirms no MCP/graph anywhere.
- Sandboxed install `HOME=/tmp/sift-home bash install.sh` → exit 0; produced only `~/.claude/{CLAUDE.md,settings.json,settings.local.json,skills/*,case-templates,analysis-scripts}`; `settings.json` validates as JSON.
- Smoke test: `file`/`md5sum`/`strings` (all in SIFT's allowlist) on a throwaway `/tmp/sift-smoke.bin` → ran cleanly.
- Our wrap targets confirmed present: `hunt.py:run_hunt` (L417), `QUERIES` (31 hunts), `neo4j_client.py` `query(timeout=)` (L144) / `query_guarded` (L158) / `stats_query_timeout` (L23) / `run_with_retry` (L50); console script `forensics-ingest = forensics.cli:main`.
- **Our Neo4j graph and `~/.claude` were not touched.** Inspection was read-only; the install was sandboxed to `/tmp`.
