"""Read-only Neo4j forensics MCP server (``forensics-mcp``).

Exposes our cross-host forensic graph (hunts + correlation queries) to a Claude
Code agent as **architecturally read-only** MCP tools, extending Protocol SIFT
(which gives per-artifact tool access but no cross-host correlation). See
``docs/protocol-sift-integration.md``.

Design guarantees (judged criteria — see that doc):
- **Architectural read-only.** This server registers *no* write tool. The only
  free-form path (``query_graph``) runs in an explicit Neo4j READ transaction
  (``default_access_mode=READ``) — the driver/server rejects writes regardless
  of the text — and is additionally guarded by a lexical write/DDL pre-check.
- **Inference constraint.** The primary interface is constrained, named hunts
  (``run_hunt``) and per-host summaries; ``query_graph`` is a guarded escape
  hatch, not the default.
- **Traceability.** ``get_event(event_id)`` resolves a finding to its source
  WindowsEvent (channel/source artifact); hunts carry ``event_id``/``channel``
  where the underlying query is per-event.
- **Audit.** Every tool call appends a JSON line to the audit log.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from forensics.hunt import (
    CASE_PARAM_HUNTS,
    EXCLUSION_PARAM_HUNTS,
    QUERIES,
    load_exclusion_params,
)
from forensics.neo4j_client import Neo4jClient, _is_timeout, stats_query_timeout

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
_CYPHER_AUDIT_TRUNC = 200

# --------------------------------------------------------------------------- #
# Hunt catalog — descriptions/categories overlaid on hunt.py's QUERIES (source
# of truth). Unlisted hunts still appear, with a name-derived description.
# --------------------------------------------------------------------------- #

HUNT_CATALOG: dict[str, tuple[str, str]] = {
    # name: (category, description)
    "summary": ("overview", "Per-host node/edge counts (processes, events, connections)."),
    "event_coverage": ("overview", "WindowsEvent counts by event ID and channel."),
    "findings_summary": ("overview", "Recorded Finding nodes for the case."),
    "suspicious_processes": ("execution", "Non-core executables seen running (name heuristic)."),
    "process_tree": ("execution", "Parent→child process spawn chains."),
    "sysmon_process_spawn": ("execution", "Sysmon EID 1 parent→child spawns (projected)."),
    "suspicious_execution_ancestry": ("execution", "Behaviorally suspicious process ancestry."),
    "execution_corroboration": (
        "execution",
        "Cross-source execution evidence (shimcache/prefetch).",
    ),
    "prefetch_sensitive_paths": ("execution", "Prefetch entries referencing sensitive paths."),
    "shimcache_staging": ("execution", "Shimcache entries in staging/temp locations."),
    "lateral_logons": ("lateral_movement", "Network/RDP logons (4624 type 3/10)."),
    "psexec_lateral": ("lateral_movement", "PsExec lateral movement (EXECUTED + 7045 service)."),
    "lateral_tool_reuse": ("lateral_movement", "Same tool executed across multiple hosts."),
    "credential_tooling": ("credential_access", "Credential-theft tooling (name heuristic)."),
    "failed_logons": ("credential_access", "Failed logon attempts (4625) — brute force."),
    "registry_persistence": ("persistence", "Registry Run/Services modifications (Sysmon 12/13)."),
    "service_install": ("persistence", "New service installs (7045)."),
    "log_cleared": ("anti_forensics", "Event-log-cleared records (EID 104)."),
    "powershell_script": ("powershell", "PowerShell script-block content (4104)."),
    "external_connections": ("c2_network", "Non-RFC1918 outbound connections."),
    "dns_queries": ("c2_network", "DNS queries (Sysmon EID 22) → resolved domains."),
    "cloud_sync_connections": (
        "c2_network",
        "Connections by cloud-sync clients (OneDrive/Drive/…).",
    ),
    "sysmon_file_touch": ("filesystem", "Sysmon file create/delete (EID 11/23)."),
    "after_hours_logons": ("anomaly", "Logons (4624) for after-hours review."),
    "usb_insertions": ("exfil", "USB device insertions."),
    "sensitive_file_touch": ("exfil", "Access to sensitive/flagged files."),
    "bulk_dns_corroboration": ("c2_network", "bulk_extractor DNS corroboration."),
    "bulk_exfil_signals": ("exfil", "bulk_extractor exfil indicators."),
    "photos_outside_home": ("media", "Photos geotagged away from home (insider cases)."),
    "photos_during_vacation": ("media", "Photos taken during a vacation window."),
    "sync_volume_spike": ("media", "Cloud-sync volume spikes by day."),
}


def list_hunts() -> list[dict[str, str]]:
    """All available hunts (from hunt.py QUERIES) with description + category."""
    out: list[dict[str, str]] = []
    for name in sorted(QUERIES):
        category, desc = HUNT_CATALOG.get(name, ("other", f"Hunt '{name}'."))
        out.append({"name": name, "category": category, "description": desc})
    return out


# --------------------------------------------------------------------------- #
# Pure guards (unit-tested without a driver)
# --------------------------------------------------------------------------- #

# Write/DDL clause keywords, matched as whole words after comment-stripping.
# Over-rejection is the safe direction for a read-only server.
_WRITE_WORD_RE = re.compile(
    r"\b(create|merge|delete|set|remove|drop|detach|foreach)\b", re.IGNORECASE
)
_LOAD_CSV_RE = re.compile(r"\bload\s+csv\b", re.IGNORECASE)
_IN_TX_RE = re.compile(r"\bin\s+transactions\b", re.IGNORECASE)
# apoc / db procedures whose name contains a write verb
_PROC_WRITE_RE = re.compile(
    r"\b(?:apoc|db|dbms)\.[a-z0-9_.]*"
    r"(create|merge|delete|set|remove|refactor|drop|add|rename|commit|install|restore)",
    re.IGNORECASE,
)


def strip_comments(cypher: str) -> str:
    """Remove // line comments and /* */ block comments (so they can't hide writes)."""
    no_block = re.sub(r"/\*.*?\*/", " ", cypher, flags=re.DOTALL)
    no_line = re.sub(r"//[^\n]*", " ", no_block)
    return no_line


def reject_write(cypher: str) -> str | None:
    """Return a rejection reason if the query contains any write/DDL construct, else None.

    Lexical defense-in-depth on top of the READ transaction. Runs against the
    comment-stripped text so commented-out / hidden writes are still caught.
    """
    scrubbed = strip_comments(cypher)
    m = _WRITE_WORD_RE.search(scrubbed)
    if m:
        return f"write/DDL keyword '{m.group(1).upper()}' is not permitted"
    if _LOAD_CSV_RE.search(scrubbed):
        return "LOAD CSV is not permitted"
    if _IN_TX_RE.search(scrubbed):
        return "CALL { ... } IN TRANSACTIONS is not permitted"
    if _PROC_WRITE_RE.search(scrubbed):
        return "write procedures (apoc/db.*) are not permitted"
    return None


_LIMIT_RE = re.compile(r"\blimit\s+\d+", re.IGNORECASE)


def enforce_limit(cypher: str, cap: int) -> tuple[str, bool]:
    """Ensure the query has a LIMIT; append ``LIMIT cap`` if absent.

    Returns (possibly-rewritten cypher, appended?). Row results are *also* capped
    in Python by the caller, which covers UNION/multi-part queries where a single
    appended LIMIT would only bind the last part.
    """
    if _LIMIT_RE.search(strip_comments(cypher)):
        return cypher, False
    trimmed = cypher.rstrip().rstrip(";").rstrip()
    return f"{trimmed}\nLIMIT {cap}", True


def _clamp_limit(limit: int) -> int:
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_LIMIT
    return max(1, min(limit, MAX_LIMIT))


# --------------------------------------------------------------------------- #
# Audit log (append-only JSON lines; never blocks a call on failure)
# --------------------------------------------------------------------------- #


def audit_path() -> str:
    return os.environ.get("FORENSICS_MCP_AUDIT", "investigation/mcp-audit.log")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_args(args: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in args.items():
        if k == "cypher" and isinstance(v, str):
            out[k] = v[:_CYPHER_AUDIT_TRUNC]
        else:
            out[k] = v
    return out


def write_audit(entry: dict[str, Any]) -> None:
    """Append one JSON line to the audit log. Never raises; logs failure to stderr."""
    path = audit_path()
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
    except Exception as exc:  # noqa: BLE001 - audit must never block a tool call
        print(f"[forensics-mcp] audit write failed: {exc}", file=sys.stderr)


def _with_audit(tool: str, args: dict[str, Any], work: Callable[[], dict | list]) -> dict | list:
    t0 = time.perf_counter()
    try:
        result: dict | list = work()
    except Exception as exc:  # noqa: BLE001 - surface as typed error, still audit
        result = {"error": str(exc), "error_type": "internal_error"}
    dur = round((time.perf_counter() - t0) * 1000, 1)
    status = "ok"
    row_count: int | None = None
    if isinstance(result, dict):
        result.setdefault("duration_ms", dur)
        if result.get("error"):
            status = str(result.get("error_type", "error"))
        row_count = result.get("row_count")
    elif isinstance(result, list):
        row_count = len(result)
    write_audit(
        {
            "ts": _now_iso(),
            "tool": tool,
            "args": _safe_args(args),
            "duration_ms": dur,
            "status": status,
            "row_count": row_count,
        }
    )
    return result


# --------------------------------------------------------------------------- #
# Tool implementations (client injected → unit-testable without a live driver)
# --------------------------------------------------------------------------- #


def _err(error_type: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"error": message, "error_type": error_type, **extra}


def impl_run_hunt(client: Neo4jClient, name: str, limit: int = DEFAULT_LIMIT) -> dict[str, Any]:
    if name not in QUERIES:
        return _err(
            "unknown_hunt",
            f"unknown hunt '{name}'; call list_hunts() for the available set",
            available=sorted(QUERIES),
        )
    if name in CASE_PARAM_HUNTS:
        return _err(
            "needs_case",
            f"hunt '{name}' needs case parameters not available via the MCP server",
        )
    cap = _clamp_limit(limit)
    params = load_exclusion_params(name) if name in EXCLUSION_PARAM_HUNTS else None
    try:
        rows = client.read_query(QUERIES[name], params, timeout=stats_query_timeout())
    except Exception as exc:  # noqa: BLE001
        if _is_timeout(exc):
            return _err("timeout", "hunt exceeded the server-side time limit; narrow it")
        return _err("query_error", f"hunt failed: {exc}")
    truncated = len(rows) > cap
    return {
        "hunt": name,
        "rows": rows[:cap],
        "row_count": min(len(rows), cap),
        "truncated": truncated,
    }


def impl_get_host_summary(client: Neo4jClient, hostname: str) -> dict[str, Any]:
    timeout = stats_query_timeout()
    exists = client.read_query(
        "MATCH (h:Host {hostname: $h}) RETURN count(h) AS c", {"h": hostname}, timeout=timeout
    )
    if not exists or int(exists[0]["c"]) == 0:
        hosts = client.read_query("MATCH (h:Host) RETURN h.hostname AS host ORDER BY host")
        return _err(
            "unknown_host",
            f"host '{hostname}' not found",
            available=[r["host"] for r in hosts],
        )
    p = {"h": hostname}
    events = client.read_query(
        "MATCH (:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $h}) RETURN count(*) AS c",
        p,
        timeout=timeout,
    )
    procs = client.read_query(
        "MATCH (h:Host {hostname: $h})<-[:RAN_ON]-(p:Process) RETURN count(p) AS c",
        p,
        timeout=timeout,
    )
    by_eid = client.read_query(
        """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $h})
        RETURN e.eventId AS event_id, count(*) AS count
        ORDER BY count DESC LIMIT 25
        """,
        p,
        timeout=timeout,
    )
    # per-relationship anchored edge counts (single-relationship scans; no stacking)
    edge_q = {
        "spawned_sysmon": "MATCH (h:Host {hostname:$h})<-[:RAN_ON]-(:Process)"
        "-[r:SPAWNED {source:'sysmon'}]->(:Process) RETURN count(r) AS c",
        "connected_to": "MATCH (h:Host {hostname:$h})<-[:RAN_ON]-(:Process)"
        "-[r:CONNECTED_TO]->(:IPAddress) RETURN count(r) AS c",
        "modified_registry": "MATCH (h:Host {hostname:$h})<-[:RAN_ON]-(:Process)"
        "-[r:MODIFIED]->(:RegistryKey) RETURN count(r) AS c",
        "created_file": "MATCH (h:Host {hostname:$h})<-[:REPORTED]-(:WindowsEvent)"
        "-[r:CREATED_FILE]->(:File) RETURN count(r) AS c",
        "logged_in": "MATCH (:UserAccount)-[r:LOGGED_IN]->(h:Host {hostname:$h}) RETURN count(r) AS c",
    }
    edges = {}
    for key, q in edge_q.items():
        rows = client.read_query(q, p, timeout=timeout)
        edges[key] = int(rows[0]["c"]) if rows else None
    return {
        "hostname": hostname,
        "total_events": int(events[0]["c"]) if events else 0,
        "process_count": int(procs[0]["c"]) if procs else 0,
        "events_by_event_id": by_eid,
        "relationship_counts": edges,
        "row_count": len(by_eid),
    }


def impl_get_event(client: Neo4jClient, event_id: str) -> dict[str, Any]:
    rows = client.read_query(
        """
        MATCH (e:WindowsEvent {id: $id})
        OPTIONAL MATCH (e)-[:REPORTED]->(h:Host)
        RETURN e {.*} AS event, h.hostname AS host
        LIMIT 1
        """,
        {"id": event_id},
        timeout=stats_query_timeout(),
    )
    if not rows:
        return _err(
            "not_found",
            f"no WindowsEvent with id '{event_id}'. The id scheme is "
            "'<HOSTNAME>:<record_number>' (e.g. 'SRL-DC:2952977').",
        )
    event = rows[0]["event"] or {}
    event["host"] = rows[0].get("host")
    return {"event_id": event_id, "event": event, "row_count": 1}


def impl_query_graph(
    client: Neo4jClient,
    cypher: str,
    params: dict[str, Any] | None = None,
    limit_enforced: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    if not isinstance(cypher, str) or not cypher.strip():
        return _err("bad_request", "cypher must be a non-empty string")
    reason = reject_write(cypher)
    if reason:
        return _err(
            "write_rejected",
            f"write operations are not available on this server: {reason}. "
            "This is a read-only forensic graph — use a MATCH/RETURN query, or "
            "call run_hunt() for a vetted query.",
        )
    cap = _clamp_limit(limit_enforced)
    effective, appended = enforce_limit(cypher, cap)
    try:
        rows = client.read_query(effective, params or {}, timeout=stats_query_timeout())
    except Exception as exc:  # noqa: BLE001
        if _is_timeout(exc):
            return _err(
                "timeout",
                "query exceeded the server-side time limit; anchor it on a Host "
                "and add a tighter LIMIT, or use a named hunt via run_hunt().",
            )
        # a write that slipped past the lexical check is still rejected by the
        # READ transaction at the driver/server layer → surface as write_rejected.
        # Neo4j phrases this "Writing in read access mode not allowed".
        msg = str(exc).lower()
        if "read access mode" in msg or ("writ" in msg and "read" in msg):
            return _err(
                "write_rejected",
                "write operations are not available on this server (read transaction).",
            )
        return _err("query_error", f"query failed: {exc}")
    truncated = len(rows) > cap or appended
    return {
        "rows": rows[:cap],
        "row_count": min(len(rows), cap),
        "truncated": truncated,
        "limit_applied": cap,
    }


# --------------------------------------------------------------------------- #
# FastMCP server wiring
# --------------------------------------------------------------------------- #

_client: Neo4jClient | None = None


def _shared_client() -> Neo4jClient:
    global _client
    if _client is None:
        _client = Neo4jClient()
    return _client


def build_server():
    """Construct the FastMCP server with the five read-only tools registered."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("forensics-graph")

    @mcp.tool(name="list_hunts")
    def _list_hunts() -> list[dict[str, str]]:
        """List available forensic hunts (name, category, description). Read-only."""
        return _with_audit("list_hunts", {}, list_hunts)  # type: ignore[return-value]

    @mcp.tool(name="run_hunt")
    def _run_hunt(name: str, limit: int = DEFAULT_LIMIT) -> dict[str, Any]:
        """Run a named, vetted forensic hunt and return rows + metadata. Read-only."""
        return _with_audit(  # type: ignore[return-value]
            "run_hunt",
            {"name": name, "limit": limit},
            lambda: impl_run_hunt(_shared_client(), name, limit),
        )

    @mcp.tool(name="get_host_summary")
    def _get_host_summary(hostname: str) -> dict[str, Any]:
        """Per-host anchored summary: events by EID, process count, key edge counts."""
        return _with_audit(  # type: ignore[return-value]
            "get_host_summary",
            {"hostname": hostname},
            lambda: impl_get_host_summary(_shared_client(), hostname),
        )

    @mcp.tool(name="get_event")
    def _get_event(event_id: str) -> dict[str, Any]:
        """Resolve a finding to its source WindowsEvent by id (traceability primitive)."""
        return _with_audit(  # type: ignore[return-value]
            "get_event",
            {"event_id": event_id},
            lambda: impl_get_event(_shared_client(), event_id),
        )

    @mcp.tool(name="query_graph")
    def _query_graph(
        cypher: str, params: dict[str, Any] | None = None, limit_enforced: int = DEFAULT_LIMIT
    ) -> dict[str, Any]:
        """Run a READ-ONLY Cypher query (guarded escape hatch). Writes are rejected."""
        return _with_audit(  # type: ignore[return-value]
            "query_graph",
            {"cypher": cypher, "limit_enforced": limit_enforced},
            lambda: impl_query_graph(_shared_client(), cypher, params, limit_enforced),
        )

    return mcp


def main() -> None:
    server = build_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
