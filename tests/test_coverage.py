"""Tests for the rewritten (anchored, guarded) ingest coverage stats.

The old graph_edges query stacked five OPTIONAL MATCH patterns into one
Cartesian blow-up. It is now five separate Host-anchored counts, each run
through a timeout guard so a slow/broken metric is skipped, not hung.
"""

from __future__ import annotations

from types import SimpleNamespace

from forensics.coverage import _GRAPH_EDGE_QUERIES, gather_coverage_metrics
from forensics.registry import IngestReport


class FakeClient:
    """Records query_guarded calls; times out any query containing `timeout_on`."""

    def __init__(self, timeout_on: str | None = None) -> None:
        self.calls: list[tuple[str, dict | None, float | None]] = []
        self.timeout_on = timeout_on

    def query_guarded(self, cypher, parameters=None, *, timeout=None):
        self.calls.append((cypher, parameters, timeout))
        if self.timeout_on and self.timeout_on in cypher:
            return None, "timeout"
        # One fat row satisfies every consumer (each reads only its own keys).
        return [
            {
                "c": 7,
                "total": 0,
                "cataloged": 0,
                "sensitive": 0,
                "with_gps": 0,
                "usb_devices": 0,
                "bulk_refs": 0,
                "eventId": 4624,
                "channel": "Security",
                "cnt": 3,
            }
        ], "ok"


def _case():
    return SimpleNamespace(case_type="intrusion")


def _report():
    return IngestReport(hostname="SRL-WKSTN01")


def test_graph_edges_split_into_five_anchored_queries():
    # each query is anchored on the Host node and scans exactly one relationship
    assert set(_GRAPH_EDGE_QUERIES) == {
        "spawned_sysmon",
        "connected_sysmon",
        "created_files",
        "dns_resolved",
        "registry_modified",
    }
    for cypher in _GRAPH_EDGE_QUERIES.values():
        assert "Host {hostname: $hostname}" in cypher
        assert "OPTIONAL MATCH" not in cypher  # no stacked optionals


def test_coverage_all_ok_populates_graph_edges_and_no_skips():
    client = FakeClient()
    out = gather_coverage_metrics(_case(), _report(), client)
    assert out["graph_edges"] == {
        "spawned_sysmon": 7,
        "connected_sysmon": 7,
        "created_files": 7,
        "dns_resolved": 7,
        "registry_modified": 7,
    }
    assert out["stats_skipped"] == []
    # every metric ran under a timeout (last positional/kw arg present)
    assert all(call[2] is not None for call in client.calls)


def test_coverage_timeout_skips_one_metric_and_continues():
    # the SPAWNED edge count times out; everything else still computes
    client = FakeClient(timeout_on="SPAWNED")
    out = gather_coverage_metrics(_case(), _report(), client)
    assert out["graph_edges"]["spawned_sysmon"] is None  # skipped -> null
    assert out["graph_edges"]["registry_modified"] == 7  # others fine
    assert "graph_edges.spawned_sysmon:timeout" in out["stats_skipped"]
    # the function returned a full result despite the timeout
    assert out["event_coverage"] and "files_total" in out
