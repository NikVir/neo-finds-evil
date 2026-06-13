# Architecture

`neo-finds-evil` adds **one** component to a Protocol SIFT deployment: a read-only MCP server (`forensics-graph`) that exposes a Neo4j correlation graph to the same Claude Code agent that already drives Protocol SIFT's per-artifact tools. This document describes the components, the data/control flow, and (most importantly for the hackathon's scoring) exactly **which guardrails are architectural vs. prompt/config-based**.

The diagram referenced from the README lives alongside this file: **`docs/architecture.png`**.

---

## Components

```
                          ┌─────────────────────────────────────────┐
                          │            Claude Code agent             │
                          │  governed by Protocol SIFT's global      │
                          │  CLAUDE.md operating rules (read-only,    │
                          │  court-defensible, self-correcting)       │
                          └───────────────┬─────────────────────────-┘
                  ┌───────────────────────┴───────────────────────────┐
        existing: Protocol SIFT                       NEW: this project
                  │                                           │
                  ▼                                           ▼
    ┌───────────────────────────────┐         ┌──────────────────────────────────┐
    │  Bash + Skills tool layer      │         │  forensics-graph MCP server        │
    │  vol.py / log2timeline / TSK / │         │  (stdio; the ONLY MCP server)      │
    │  EZ Tools / yara — ONE         │         │  5 read-only tools:                │
    │  artifact, ONE host at a time  │         │  list_hunts · run_hunt ·           │
    │                                │         │  get_host_summary · get_event ·    │
    │                                │         │  query_graph (read-tx)             │
    └───────────────┬───────────────┘         └────────────────┬─────────────────┘
                    ▼                                           ▼
       ┌──────────────────────────┐              ┌──────────────────────────────────┐
       │ read-only evidence mounts │              │ Neo4j graph (5.x Community)        │
       │ /mnt/… -o ro (disk images)│   ◀── built  │ all artifacts × all hosts ×        │
       │                          │     by  ───▶  │ full timeline                      │
       └──────────────────────────┘   Phase-1     │ ~359,788 nodes / ~1.9M edges       │
                                       ingest      └──────────────────────────────────┘
```

1. **Claude Code agent (under Protocol SIFT's `CLAUDE.md`).** The orchestrator. Protocol SIFT's global config sets its DFIR posture: read-only evidence handling, autonomous operation, a self-correction directive ("read stderr → hypothesize → correct → retry"), and a tool→skill routing table. This project does not change that posture; it adds tools the agent can call under it.

2. **Protocol SIFT's Bash/Skill tool layer (existing).** Pre-approved forensic CLIs plus five skill playbooks. Deep on a single artifact/host; **no cross-host or cross-time memory**. This is the capability this project complements.

3. **The `forensics-graph` MCP server (this project), the ONLY MCP server.** A Python (`mcp`/FastMCP) server over **stdio**, registered project-scoped via `.mcp.json`. It exposes exactly five **read-only** tools (`list_hunts`, `run_hunt`, `get_host_summary`, `get_event`, `query_graph`). It is the agent's *only* window into the correlation graph, and it is read-only by construction (see Security boundaries).

4. **The Neo4j correlation graph.** Neo4j 5.x Community. Hosts, processes, Windows events, files, registry keys, IP addresses, domains, services, and user accounts as nodes; `REPORTED`, `RAN_ON`, `SPAWNED`, `CONNECTED_TO`, `LOGGED_IN`, `MODIFIED`/`MODIFIED_REGISTRY`, `CREATED_FILE`, `RESOLVED_DNS`, `INSTALLED_SERVICE`, etc. as edges. Scale and provenance: `docs/evidence-dataset.md`.

5. **Read-only evidence mounts.** Disk images mounted `-o ro`; the Phase-1 ingest pipeline (`src/forensics/ingest/`) reads them, normalizes artifacts, and **writes the graph out-of-band**. The *agent* never has a write path to either evidence or graph.

---

## Data / control flow

**Build time (out-of-band, not agent-driven):** evidence images → Phase-1 loaders (EVTX, shimcache, prefetch, pslist/psscan/netscan/dlllist, MFT, bulk_extractor, registry) → normalization + de-duplication + relationship projection → Neo4j graph. The agent is **not** involved and has **no** ingest/write tool. Keeping the write path out of the agent entirely is itself an architectural guardrail.

**Investigation time (agent-driven, read-only):**

1. The agent calls `list_hunts` / `run_hunt` (the safe, vetted default) or `query_graph` (guarded escape hatch) to reason across hosts and time.
2. Each call runs in a Neo4j **READ transaction** with a server-side timeout and a mandatory `LIMIT`; every call appends a JSON line to the audit log.
3. A finding (a hunt row) carries an `event_id`; the agent calls `get_event(event_id)` to resolve it to the **source `WindowsEvent`**, including `channel`, i.e. the originating `.evtx` that a Protocol SIFT tool (EvtxECmd/plaso) would have parsed. **Traceability therefore spans both layers.**
4. On error, the tool returns a *typed* error with a remediation hint, and the agent self-corrects its next call.

---

## Security boundaries

The hackathon explicitly scores **architectural vs. prompt/config-based** guardrails. Here is the honest split for the whole deployment.

### Architectural (server-enforced, a property of the system, not a request to the agent)

- **No write tool exists.** The `forensics-graph` server registers only the five read tools. There is no MCP affordance (none) for the agent to `CREATE`/`MERGE`/`SET`/`DELETE`/`DROP` graph data or to ingest. The dangerous action is **not expressible** through the tool surface. *(Implemented in `src/forensics/mcp_server.py:build_server`.)*
- **`query_graph` runs in a READ transaction.** The free-form path opens its session with `default_access_mode=READ` and an explicit read transaction (`Neo4jClient.read_query`). The Neo4j driver/server **rejects any write regardless of the query text**, including a write that slips past the lexical pre-check (it surfaces as `write_rejected`). **This is the true boundary.**
- **Project-scoped registration (`.mcp.json`).** The server is registered per-project, not by mutating Protocol SIFT's global config, so neither framework's configuration clobbers the other, and the read-only server is the only graph access the project grants.
- **Write path is out-of-band.** Graph construction happens in the Phase-1 pipeline, never via an agent tool.

### Defense-in-depth (still server-side, but a list rather than a property)

- **Lexical write/DDL pre-check.** Before execution, `query_graph` comment-strips and whole-word-matches `CREATE/MERGE/DELETE/SET/REMOVE/DROP/DETACH/FOREACH`, `LOAD CSV`, `CALL { … } IN TRANSACTIONS`, and apoc/db write procedures, and rejects them with a typed error. This **intentionally over-rejects** (a benign query containing a write keyword as a substring can be refused). For a read-only forensic server, over-rejection is the safe direction, and it is *backstopped* by the READ transaction above. A 21-case bypass battery (`tests/test_mcp_server.py`) exercises lowercase/mixed-case/comment-hidden/after-`WITH`/`UNION`/`CALL`-subquery/apoc variants.
- **Resource bounds.** Server-side query timeout + mandatory `LIMIT` (appended when absent; rows also capped in Python for `UNION`/multi-part queries).
- **Audit.** Every tool call appends `{ts, tool, args, duration_ms, status, row_count}` to the audit log (a sanitized sample is in `docs/execution-logs/`).

### Prompt / config-based (inherited from Protocol SIFT, *not* a property of this server)

- **Operating posture** ("never modify evidence", read-only, court-defensible) is set by Protocol SIFT's global `CLAUDE.md`, instruction-level.
- **Tool access for the *forensic CLIs*** is governed by Protocol SIFT's `settings.json` allow/deny lists for the `Bash` tool, i.e. "run anything via Bash, minus a denylist." That is config-enforced, and it is precisely the gap this project's MCP layer closes for *graph* access: where SIFT's tool layer is "Bash gated by a denylist," ours is "a tool surface with no write verb in it."
- **OS-level** evidence integrity rests on mounting images `-o ro`.

**Net:** the contribution that scores on the "architectural guardrails" axis is that **graph access is read-only because of what the tools *are*, not because of what the agent is *told***. The README's *The architectural read-only guardrail* section summarizes the three layers; the live write-rejection transcript is in `protocol-sift-integration.md` §4.0.
