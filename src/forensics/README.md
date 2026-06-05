# `forensics` package

The Python package behind this project. See the **[top-level README](../../README.md)** for the judge runbook (graph restore, MCP registration, the demo question) and **[docs/architecture.md](../../docs/architecture.md)** for the design.

## What's here

| Module | Role |
|---|---|
| `mcp_server.py` | **The read-only `forensics-graph` MCP server** (console script `forensics-mcp`). Five tools: `list_hunts`, `run_hunt`, `get_host_summary`, `get_event`, `query_graph`. |
| `hunt.py` | The vetted hunt catalog (`QUERIES`) that `run_hunt` / `list_hunts` expose. |
| `neo4j_client.py` | Read-only Neo4j client — READ transactions, server-side timeout, retry. |
| `ingest/` | Phase-1 pipeline that builds the graph (one loader per artifact type). Runs out-of-band; never exposed as an agent tool. |
| `playbooks/` | Multi-hunt investigation playbooks. |
| `correlate.py`, `correlate_artifacts.py` | Post-ingest relationship projection / corroboration. |

## Entry points (`pyproject.toml`)

```
forensics-mcp     = forensics.mcp_server:main     # the MCP server (stdio)
forensics-ingest  = forensics.cli:main            # the graph-build CLI
```

## Hunts

The full catalog is the `QUERIES` dict in [`hunt.py`](hunt.py); categories and descriptions are surfaced by `list_hunts`. Two behavioral hunts (`lateral_tool_reuse`, `credential_tooling`) read their denylists/dictionaries from [`config/exclusions.yaml`](../../config/exclusions.yaml).

> Read-only by construction: the MCP server registers no write tool, and `query_graph` runs inside a Neo4j READ transaction. See *Security boundaries* in [docs/architecture.md](../../docs/architecture.md).
