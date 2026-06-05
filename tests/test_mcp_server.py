"""Tests for the read-only forensics MCP server.

The headline test is ``test_query_graph_write_rejection_bypass_battery`` — the
"tested for bypass" evidence for the architectural-read-only guardrail.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forensics import mcp_server as m


class _Exc(Exception):
    def __init__(self, msg: str, code: str = "") -> None:
        super().__init__(msg)
        self.code = code


class FakeClient:
    """Stand-in for Neo4jClient.read_query: canned responder or raises."""

    def __init__(self, responder=None, raise_exc=None) -> None:
        self.calls: list[tuple[str, dict | None, float | None]] = []
        self.responder = responder
        self.raise_exc = raise_exc

    def read_query(self, cypher, parameters=None, *, timeout=None):
        self.calls.append((cypher, parameters, timeout))
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.responder(cypher, parameters) if self.responder else []


# --------------------------------------------------------------------------- #
# pure guards
# --------------------------------------------------------------------------- #

# Every one of these MUST be rejected. Covers: plain writes, lowercase, mixed
# case, leading whitespace, // and /* */ comments hiding a write, writes after
# WITH / UNION, CALL {} subqueries, CALL {} IN TRANSACTIONS, apoc write procs,
# FOREACH, LOAD CSV, DROP/REMOVE/DETACH DELETE.
_BYPASS_BATTERY = [
    "MATCH (n) MERGE (m) RETURN n",
    "create (n)",
    "MATCH (n) DELETE n",
    "MATCH (n) DETACH DELETE n",
    "MATCH (n) SET n.x = 1 RETURN n",
    "MATCH (n) REMOVE n.x RETURN n",
    "DROP INDEX foo IF EXISTS",
    "   \n   MERGE (n) RETURN n",
    "/* harmless */ CREATE (n) RETURN n",
    "MATCH (n) // comment\nCREATE (m) RETURN n",
    "MATCH (n) /* x */ DELETE n",
    "MATCH (n) WITH n CREATE (m) RETURN m",
    "MATCH (n) RETURN n UNION MATCH (x) CREATE (y) RETURN y",
    "MATCH (n) CALL { CREATE (m) } RETURN n",
    "CALL { MATCH (n) DELETE n } IN TRANSACTIONS",
    "MaTcH (n) MeRgE (m) RETURN n",
    "MATCH (n) FOREACH (i IN [1] | SET n.y = i) RETURN n",
    "LOAD CSV FROM 'f.csv' AS row CREATE (n) RETURN n",
    "CALL apoc.create.node(['L'], {}) YIELD node RETURN node",
    "CALL apoc.refactor.cloneNodes([]) YIELD output RETURN output",
    "MATCH (n) CALL apoc.merge.node(['L'],{}) YIELD node RETURN node",
]


@pytest.mark.parametrize("cypher", _BYPASS_BATTERY)
def test_query_graph_write_rejection_bypass_battery(cypher):
    # the pure guard rejects it
    assert m.reject_write(cypher) is not None, f"NOT rejected by guard: {cypher!r}"
    # and impl_query_graph rejects without ever touching the client
    client = FakeClient(raise_exc=AssertionError("client must not be called on a write"))
    out = m.impl_query_graph(client, cypher)
    assert out["error_type"] == "write_rejected"
    assert "read-only" in out["error"]
    assert client.calls == []  # short-circuited before any DB access


_ALLOWED = [
    "MATCH (h:Host) RETURN h.hostname LIMIT 5",
    "MATCH (e:WindowsEvent) WHERE e.eventId = 4624 RETURN e.id LIMIT 10",
    "MATCH (n) RETURN n.settings, n.offset, n.subset LIMIT 1",  # 'set' substrings not whole-word
]


@pytest.mark.parametrize("cypher", _ALLOWED)
def test_reject_write_allows_read_queries(cypher):
    assert m.reject_write(cypher) is None


def test_enforce_limit_appends_when_absent():
    out, appended = m.enforce_limit("MATCH (n) RETURN n", 100)
    assert appended is True and out.strip().endswith("LIMIT 100")


def test_enforce_limit_keeps_existing():
    out, appended = m.enforce_limit("MATCH (n) RETURN n LIMIT 3", 100)
    assert appended is False and out == "MATCH (n) RETURN n LIMIT 3"


def test_clamp_limit():
    assert m._clamp_limit(50) == 50
    assert m._clamp_limit(0) == 1
    assert m._clamp_limit(10_000) == m.MAX_LIMIT
    assert m._clamp_limit("nope") == m.DEFAULT_LIMIT


# --------------------------------------------------------------------------- #
# list_hunts
# --------------------------------------------------------------------------- #


def test_list_hunts_covers_queries_with_category():
    from forensics.hunt import QUERIES

    hunts = m.list_hunts()
    assert {h["name"] for h in hunts} == set(QUERIES)
    assert all(h["category"] and h["description"] for h in hunts)


# --------------------------------------------------------------------------- #
# run_hunt
# --------------------------------------------------------------------------- #


def test_run_hunt_happy_truncates():
    client = FakeClient(responder=lambda c, p: [{"event_id": f"SRL-DC:{i}"} for i in range(5)])
    out = m.impl_run_hunt(client, "failed_logons", limit=2)
    assert out["hunt"] == "failed_logons"
    assert out["row_count"] == 2 and out["truncated"] is True
    assert len(out["rows"]) == 2


def test_run_hunt_unknown_name():
    out = m.impl_run_hunt(FakeClient(), "not_a_hunt")
    assert out["error_type"] == "unknown_hunt" and "available" in out


def test_run_hunt_needs_case_hunt_rejected():
    # photos_* hunts need case params not available via MCP
    out = m.impl_run_hunt(FakeClient(), "photos_outside_home")
    assert out["error_type"] == "needs_case"


def test_run_hunt_timeout_typed_error():
    client = FakeClient(
        raise_exc=_Exc("timed out", code="Neo.ClientError.Transaction.TransactionTimedOut")
    )
    out = m.impl_run_hunt(client, "failed_logons")
    assert out["error_type"] == "timeout"


# --------------------------------------------------------------------------- #
# get_host_summary
# --------------------------------------------------------------------------- #


def _host_responder(cypher, params):
    c = cypher.lower()
    if "count(h) as c" in c:
        return [{"c": 1}]
    if "match (h:host) return h.hostname" in c:
        return [{"host": "SRL-DC"}, {"host": "SRL-RD02"}]
    if "-[:reported]->(h:host {hostname: $h}) return count(*)" in c:
        return [{"c": 137814}]
    if "<-[:ran_on]-(p:process) return count(p)" in c:
        return [{"c": 123}]
    if "e.eventid as event_id" in c:
        return [{"event_id": 4688, "count": 135581}]
    if "count(r) as c" in c:
        return [{"c": 7}]
    return []


def test_get_host_summary_happy():
    out = m.impl_get_host_summary(FakeClient(responder=_host_responder), "SRL-DC")
    assert out["hostname"] == "SRL-DC"
    assert out["total_events"] == 137814 and out["process_count"] == 123
    assert out["events_by_event_id"][0]["event_id"] == 4688
    assert set(out["relationship_counts"]) == {
        "spawned_sysmon",
        "connected_to",
        "modified_registry",
        "created_file",
        "logged_in",
    }


def test_get_host_summary_unknown_host():
    def responder(cypher, params):
        c = cypher.lower()
        if "count(h) as c" in c:
            return [{"c": 0}]
        if "match (h:host) return h.hostname" in c:
            return [{"host": "SRL-DC"}]
        return []

    out = m.impl_get_host_summary(FakeClient(responder=responder), "NOPE")
    assert out["error_type"] == "unknown_host" and "SRL-DC" in out["available"]


# --------------------------------------------------------------------------- #
# get_event (traceability primitive)
# --------------------------------------------------------------------------- #


def test_get_event_happy():
    client = FakeClient(
        responder=lambda c, p: [{"event": {"id": p["id"], "eventId": 4688}, "host": "SRL-DC"}]
    )
    out = m.impl_get_event(client, "SRL-DC:2952977")
    assert out["event"]["eventId"] == 4688 and out["event"]["host"] == "SRL-DC"
    assert out["row_count"] == 1


def test_get_event_not_found_explains_id_scheme():
    out = m.impl_get_event(FakeClient(responder=lambda c, p: []), "bogus")
    assert out["error_type"] == "not_found" and "record_number" in out["error"]


# --------------------------------------------------------------------------- #
# query_graph (read happy path, limit enforcement, driver-level rejection, timeout)
# --------------------------------------------------------------------------- #


def test_query_graph_read_happy_enforces_limit():
    client = FakeClient(responder=lambda c, p: [{"h": "SRL-DC"}])
    out = m.impl_query_graph(client, "MATCH (h:Host) RETURN h.hostname")
    assert out["row_count"] == 1 and out["limit_applied"] == m.DEFAULT_LIMIT
    # the executed cypher had LIMIT appended
    assert "LIMIT" in client.calls[0][0]


def test_query_graph_caps_rows():
    client = FakeClient(responder=lambda c, p: [{"i": i} for i in range(10)])
    out = m.impl_query_graph(client, "MATCH (n) RETURN n LIMIT 999", limit_enforced=3)
    assert out["row_count"] == 3 and out["truncated"] is True


def test_query_graph_driver_read_mode_rejection():
    # a write that somehow passed the lexical check is still rejected by the READ tx
    client = FakeClient(raise_exc=_Exc("Writing in read access mode not allowed"))
    out = m.impl_query_graph(client, "MATCH (n) RETURN n")  # lexically clean
    assert out["error_type"] == "write_rejected"


def test_query_graph_timeout_typed_error():
    client = FakeClient(
        raise_exc=_Exc("timeout", code="Neo.ClientError.Transaction.TransactionTimedOut")
    )
    out = m.impl_query_graph(client, "MATCH (n) RETURN n")
    assert out["error_type"] == "timeout" and "run_hunt" in out["error"]


def test_query_graph_empty_cypher():
    assert m.impl_query_graph(FakeClient(), "   ")["error_type"] == "bad_request"


# --------------------------------------------------------------------------- #
# audit log
# --------------------------------------------------------------------------- #


def test_audit_writes_one_json_line_per_call(tmp_path, monkeypatch):
    log = tmp_path / "mcp-audit.log"
    monkeypatch.setenv("FORENSICS_MCP_AUDIT", str(log))
    m._with_audit("run_hunt", {"name": "x", "limit": 5}, lambda: {"row_count": 3})
    m._with_audit("query_graph", {"cypher": "Z" * 500}, lambda: {"row_count": 1})
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 2
    e0 = json.loads(lines[0])
    assert e0["tool"] == "run_hunt" and e0["status"] == "ok" and e0["row_count"] == 3
    assert "ts" in e0 and "duration_ms" in e0
    # cypher arg truncated to 200 chars in the audit
    e1 = json.loads(lines[1])
    assert len(e1["args"]["cypher"]) == m._CYPHER_AUDIT_TRUNC


def test_audit_records_error_status(tmp_path, monkeypatch):
    log = tmp_path / "a.log"
    monkeypatch.setenv("FORENSICS_MCP_AUDIT", str(log))
    m._with_audit("query_graph", {"cypher": "MERGE (n)"}, lambda: m._err("write_rejected", "no"))
    entry = json.loads(log.read_text().strip())
    assert entry["status"] == "write_rejected"


def test_audit_never_raises_on_bad_path(monkeypatch, capsys, tmp_path):
    # Root the audit path *under a regular file* so creating its parent dir is
    # impossible (a path component is a file -> NotADirectoryError). This fails
    # for every uid, including root in Docker, where a "/nonexistent" path would
    # otherwise be creatable and the warning would never fire.
    blocker = tmp_path / "iam-a-file"
    blocker.write_text("x")
    monkeypatch.setenv("FORENSICS_MCP_AUDIT", str(blocker / "cannot" / "write.log"))
    # must not raise even though the path is unwritable
    m.write_audit({"ts": "now", "tool": "x"})
    assert "audit write failed" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# .mcp.json registration
# --------------------------------------------------------------------------- #


def test_mcp_json_valid_and_registers_server():
    root = Path(__file__).resolve().parents[1]
    cfg = json.loads((root / ".mcp.json").read_text())
    server = cfg["mcpServers"]["forensics-graph"]
    assert server["command"] == "uv"
    assert "forensics-mcp" in server["args"]
    assert server["env"]["NEO4J_DATABASE"] == "neo4j"
