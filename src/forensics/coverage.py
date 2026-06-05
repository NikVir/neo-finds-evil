"""Extended ingest coverage metrics for case types.

All queries here are REPORTING queries run at the end of each host's ingest.
They must never wedge a host: every one is anchored on the single Host node and
runs under a server-side timeout via ``client.query_guarded``. A slow or broken
metric is skipped (recorded in ``stats_skipped``) instead of hanging.

Historical note: ``graph_edges`` used to be one query with five stacked
``OPTIONAL MATCH (p:Process)-[...]->()`` patterns filtered only by
``p.id STARTS WITH $hostname``. Unanchored to the Host and stacked, that
produced a Cartesian product of the per-relationship matches (S x C x ... rows
before aggregation) and never returned on a large host (SRL-WKSTN01 hung >57min
twice on 2026-06-05). It is now five separate, individually Host-anchored
count queries — each a single relationship scan, returning in well under a
second on a ~300k-event host.
"""

from __future__ import annotations

import logging
from typing import Any

from forensics.case import CaseManifest
from forensics.neo4j_client import Neo4jClient, stats_query_timeout
from forensics.registry import IngestReport, case_coverage_notes

logger = logging.getLogger(__name__)

# Each entry: result-key -> Host-anchored, single-relationship count query.
# Anchoring on (h:Host {hostname}) uses the hostname unique index, then a bounded
# traversal of one relationship type. No stacking => no combinatorial blow-up.
_GRAPH_EDGE_QUERIES: dict[str, str] = {
    "spawned_sysmon": """
        MATCH (h:Host {hostname: $hostname})<-[:RAN_ON]-(:Process)
              -[s:SPAWNED {source: 'sysmon'}]->(:Process)
        RETURN count(s) AS c
    """,
    "connected_sysmon": """
        MATCH (h:Host {hostname: $hostname})<-[:RAN_ON]-(:Process)
              -[c:CONNECTED_TO {source: 'sysmon'}]->(:IPAddress)
        RETURN count(c) AS c
    """,
    "created_files": """
        MATCH (h:Host {hostname: $hostname})<-[:REPORTED]-(:WindowsEvent)
              -[cf:CREATED_FILE]->(:File)
        RETURN count(cf) AS c
    """,
    "dns_resolved": """
        MATCH (h:Host {hostname: $hostname})<-[:REPORTED]-(:WindowsEvent)
              -[rd:RESOLVED_DNS]->(:Domain)
        RETURN count(rd) AS c
    """,
    "registry_modified": """
        MATCH (h:Host {hostname: $hostname})<-[:RAN_ON]-(:Process)
              -[m:MODIFIED]->(:RegistryKey)
        RETURN count(m) AS c
    """,
}


def _scalar(rows: list[dict[str, Any]] | None, key: str = "c") -> int | None:
    if not rows:
        return None
    val = rows[0].get(key)
    return int(val) if val is not None else None


def gather_coverage_metrics(
    case: CaseManifest,
    report: IngestReport,
    client: Neo4jClient,
) -> dict[str, Any]:
    notes = case_coverage_notes(case.case_type, report)
    hostname = report.hostname
    timeout = stats_query_timeout()
    skipped: list[str] = []

    def guarded(label: str, cypher: str, params: dict[str, Any]) -> list[dict[str, Any]] | None:
        rows, status = client.query_guarded(cypher, params, timeout=timeout)
        if status != "ok":
            skipped.append(f"{label}:{status}")
            logger.warning("coverage stats skipped: %s on %s (%s)", label, hostname, status)
        return rows

    p = {"hostname": hostname}

    events_by_id = (
        guarded(
            "events_by_id",
            """
            MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $hostname})
            RETURN e.eventId AS eventId, e.channel AS channel, count(*) AS cnt
            ORDER BY cnt DESC
            """,
            p,
        )
        or []
    )

    # graph_edges: five separate Host-anchored counts (was one Cartesian query).
    graph_edges = {
        key: _scalar(guarded(f"graph_edges.{key}", cypher, p))
        for key, cypher in _GRAPH_EDGE_QUERIES.items()
    }

    file_stats = guarded(
        "file_stats",
        """
        MATCH (f:File)-[:ON_HOST]->(h:Host {hostname: $hostname})
        RETURN count(f) AS total,
               sum(CASE WHEN f.source = 'filestat' THEN 1 ELSE 0 END) AS cataloged,
               sum(CASE WHEN f.sensitive = true THEN 1 ELSE 0 END) AS sensitive
        """,
        p,
    )
    media_stats = guarded(
        "media_stats",
        """
        MATCH (m:MediaAsset)-[:STORED_ON]->(h:Host {hostname: $hostname})
        RETURN count(m) AS total,
               sum(CASE WHEN m.latitude IS NOT NULL THEN 1 ELSE 0 END) AS with_gps
        """,
        p,
    )
    usb_stats = guarded(
        "usb_stats",
        """
        MATCH (u:USBDevice)-[:PLUGGED_INTO]->(h:Host {hostname: $hostname})
        RETURN count(u) AS usb_devices
        """,
        p,
    )
    execution_stats = (
        guarded(
            "execution_stats",
            """
            MATCH (h:Host {hostname: $hostname})-[ex:EXECUTED]->(f:File)
            RETURN ex.source AS source, count(*) AS cnt,
                   sum(CASE WHEN ex.confidence = 'corroborated_sysmon' THEN 1 ELSE 0 END)
                       AS corroborated
            """,
            p,
        )
        or []
    )
    bulk_stats = guarded(
        "bulk_stats",
        """
        MATCH (h:Host {hostname: $hostname})-[:REFERENCED {source: 'bulk_extractor'}]->(x)
        RETURN count(x) AS bulk_refs
        """,
        p,
    )

    fs = (file_stats or [{}])[0] if file_stats else {}
    ms = (media_stats or [{}])[0] if media_stats else {}
    us = (usb_stats or [{}])[0] if usb_stats else {}
    bs = (bulk_stats or [{}])[0] if bulk_stats else {}
    total_files = int(fs.get("total") or 0)
    cataloged = int(fs.get("cataloged") or 0)
    return {
        "notes": notes,
        "events_by_id": events_by_id,
        "event_coverage": events_by_id,
        "graph_edges": graph_edges,
        "files_total": total_files,
        "files_cataloged": cataloged,
        "files_catalog_pct": round(100.0 * cataloged / total_files, 1) if total_files else 0.0,
        "files_sensitive": int(fs.get("sensitive") or 0),
        "media_total": int(ms.get("total") or 0),
        "media_with_gps": int(ms.get("with_gps") or 0),
        "usb_devices": int(us.get("usb_devices") or 0),
        "execution_by_source": execution_stats,
        "bulk_referenced": int(bs.get("bulk_refs") or 0),
        "artifact_correlation": getattr(report, "artifact_correlation", None),
        "stats_skipped": skipped,
    }
