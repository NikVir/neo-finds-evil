# Agent Execution Logs

This directory holds a **real, sanitized sample** of agent tool execution against the SRL-2018 graph, for the FIND EVIL! "Agent Execution Logs" requirement. It shows tool calls with timestamps, durations, and outcomes, and, crucially, a **self-correction** sequence.

## Primary artifact: `mcp-audit-sample.log`

Every call to the `forensics-graph` MCP server appends one JSON line to its audit log (`FORENSICS_MCP_AUDIT`, default `investigation/mcp-audit.log`). This sample is a verbatim slice of that audit trail. Each line:

```json
{"ts": "<ISO-8601 UTC>", "tool": "<tool name>", "args": {…truncated…}, "duration_ms": <float>, "status": "<ok|write_rejected|timeout|unknown_host|…>", "row_count": <int|null>}
```

| Field | Meaning |
|---|---|
| `ts` | UTC timestamp of the call (ISO-8601). |
| `tool` | One of `list_hunts`, `run_hunt`, `get_host_summary`, `get_event`, `query_graph`. |
| `args` | The call arguments; `cypher` is truncated to 200 chars in the log. |
| `duration_ms` | Wall-clock server-side duration. |
| `status` | `ok`, or a typed error (`write_rejected`, `timeout`, `unknown_hunt`, `unknown_host`, `not_found`, `query_error`, `bad_request`). |
| `row_count` | Rows returned (`null` on error). |

## How a finding traces to a tool execution

The audit log is the **execution** record; traceability to **evidence** runs through the tools themselves:

```
run_hunt / query_graph row  ──►  event_id (e.g. "SRL-DMZFTP:74648")
                                      │
                                      ▼
                              get_event(event_id)
                                      │
                                      ▼
        source WindowsEvent  ──►  channel = the .evtx on disk
                                  (what a Protocol SIFT tool, e.g. EvtxECmd/plaso, parsed)
```

So any claim in the findings can be walked back: *audit line → `event_id` → `get_event` → source artifact*. The id scheme is `<HOSTNAME>:<record_number>`.

## What the sample shows: a real self-correction trace

The sample captures the **`spsql` cross-host trace** (the README's example question), and it is a textbook self-correction:

1. **`query_graph` … `row_count: 0`**: the agent's first query guessed the wrong property names (`target_user` / `subject_user` / `user`) and returned **zero rows**. The tool reports the empty result plainly. The agent treats `0` as "wrong query," not "no evil."
2. **`query_graph` … `row_count: 10`** then **`row_count: 15`**, two **schema-discovery** queries: list node labels + counts, then sample the property keys on nodes mentioning `spsql`. The agent learns the real property names are `targetUser` / `computer` / `eventId` / `logonType`.
3. **`query_graph` … `row_count: 36`**: the **corrected** query, now grouping `spsql` activity by host/event-id/logon-type across all hosts. (A parallel `UserAccount` probe returns `0`, correctly telling the agent `spsql` exists only as event-level data, not as an account node, another honest negative.)
4. **`query_graph` … `row_count: 1`** then **`get_event` "SRL-DMZFTP:74648" … `row_count: 1`**: the agent pulls one specific failed-logon `id`, then resolves it to the **source `WindowsEvent`** (channel = `Security.evtx`) to anchor the evidence trail.

That progression (**empty result → schema discovery → corrected query → traceable source event**) is the self-correction demonstration, recorded as it actually happened.

### Guardrail line (documented elsewhere, same log format)

A prior call in the same audit format recorded the read-only guardrail firing when a write was attempted (see `../protocol-sift-integration.md` §4.0):

```json
{"ts":"2026-06-05T17:49:58.881304+00:00","tool":"query_graph","args":{"cypher":"MATCH (n) DETACH DELETE n","limit_enforced":100},"duration_ms":0.1,"status":"write_rejected","row_count":null}
```

`status: write_rejected`, `duration_ms: 0.1`. The write never reached execution.

## Claude Code session transcripts (timestamps + token usage)

Claude Code also records full session transcripts as JSON-lines, one file per session, at:

```
~/.claude/projects/<project-slug>/<session-uuid>.jsonl
```

Each assistant message carries a `timestamp` and a `usage` block with `input_tokens` / `output_tokens` (plus cache counters), so per-turn latency and token cost are recoverable. Structure (sanitized; content elided):

```json
{"type":"assistant","timestamp":"<ISO-8601>",
 "message":{"role":"assistant","content":[{"type":"tool_use","name":"mcp__forensics-graph__query_graph","input":{…}}],
            "usage":{"input_tokens":<n>,"output_tokens":<n>,"cache_read_input_tokens":<n>}}}
```

**These transcripts are intentionally NOT bundled in this repo.** A full session transcript contains the entire conversation, file contents, and agent memory, i.e. material that has not been through the redaction sweep that gates this package. The MCP **audit log** above is the purpose-built, low-sensitivity execution record and is the artifact we publish. If per-token execution accounting is needed for judging, it can be exported from the transcript path above on the operator's machine.

A sanitized per-turn export (timestamps, model, and `input` / `output` / cache token counts, with all content elided) is published as `token-usage-sample.jsonl` and `token-usage-sample.md`, generated by `tools/export_token_usage.py`.

## Supplementary trace: ntdsutil IFM finding

`ntdsutil-trace.log` is a genuine `get_event` audit line captured against the live
SRL-2018 graph, resolving the DC `ntdsutil` IFM credential-access finding
(accuracy-report §1a) to its source event `SRL-DC:7444817`. It is a separate
single-call capture, kept apart from the verbatim spsql slice above so each file
remains a faithful, unspliced record of a real run.
