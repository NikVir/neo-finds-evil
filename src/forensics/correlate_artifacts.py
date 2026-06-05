"""Post-ingest correlation for shimcache, prefetch, and bulk artifacts."""

from __future__ import annotations

from typing import Any

from forensics.case import CaseManifest
from forensics.discovery import discovery_from_case, match_score
from forensics.neo4j_client import Neo4jClient
from forensics.path_normalize import normalize_windows_path


def run_artifact_correlation(
    hostname: str,
    client: Neo4jClient,
    case: CaseManifest | None = None,
) -> dict[str, Any]:
    stats: dict[str, int] = {}

    # EXECUTED + Sysmon CREATED -> corroborated
    client.run(
        """
        MATCH (h:Host {hostname: $hostname})-[ex:EXECUTED]->(f:File)
        WHERE ex.source IN ['shimcache', 'prefetch']
        MATCH (p:Process)-[:CREATED {source: 'sysmon'}]->(f)
        WHERE p.id STARTS WITH $hostname + ':'
        SET ex.confidence = 'corroborated_sysmon'
        """,
        {"hostname": hostname},
    )
    stats["corroborated_created"] = _count(
        client,
        """
        MATCH (h:Host {hostname: $hostname})-[ex:EXECUTED {confidence: 'corroborated_sysmon'}]->(f:File)
        RETURN count(f) AS c
        """,
        {"hostname": hostname},
    )

    # EXECUTED path basename matches Sysmon EID 1 / 4688 image (exact basename, host-scoped)
    client.run(
        """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $hostname})
        WHERE e.eventId IN [1, 4688] AND e.image IS NOT NULL
        WITH e, toLower(last(split(replace(e.image, '/', '\\\\'), '\\\\'))) AS imageBase
        MATCH (f:File)<-[ex:EXECUTED]-(h)
        WHERE f.name IS NOT NULL AND toLower(f.name) = imageBase
        MERGE (e)-[:DESCRIBES]->(f)
        SET ex.confidence = coalesce(ex.confidence, 'direct')
        """,
        {"hostname": hostname},
    )
    stats["describes_events"] = _count(
        client,
        """
        MATCH (e:WindowsEvent)-[:DESCRIBES]->(f:File)
        WHERE f.id STARTS WITH $hostname + ':'
        RETURN count(DISTINCT f) AS c
        """,
        {"hostname": hostname},
    )

    # Prefetch basename weak match to Volatility Process.name
    client.run(
        """
        MATCH (h:Host {hostname: $hostname})-[ex:EXECUTED {source: 'prefetch'}]->(f:File)
        WHERE f.name IS NOT NULL
        MATCH (vp:Process)-[:RAN_ON]->(h)
        WHERE vp.name = f.name AND vp.id STARTS WITH $hostname + ':'
          AND NOT vp.id CONTAINS ':guid:'
        WITH vp, f LIMIT 500
        SET f.prefetchVolatilityMatch = true
        """,
        {"hostname": hostname},
    )

    # Bulk URL domain <-> Sysmon DNS Domain (host-scoped domains only)
    client.run(
        """
        MATCH (h:Host {hostname: $hostname})-[:REFERENCED]->(u:URL)
        WHERE u.url IS NOT NULL
        WITH h, u, toLower(
          CASE WHEN u.url CONTAINS '://'
            THEN split(split(u.url, '://')[1], '/')[0]
            ELSE split(u.url, '/')[0]
          END
        ) AS hostpart
        MATCH (d:Domain)<-[:RESOLVED_DNS|RESOLVED]-(:WindowsEvent)-[:REPORTED]->(h)
        WHERE toLower(d.name) = hostpart OR toLower(d.query) = hostpart
        MERGE (u)-[:SAME_DOMAIN]->(d)
        """,
        {"hostname": hostname},
    )
    stats["bulk_domain_links"] = _count(
        client,
        """
        MATCH (h:Host {hostname: $hostname})-[:REFERENCED]->(u:URL)-[:SAME_DOMAIN]->(:Domain)
        RETURN count(u) AS c
        """,
        {"hostname": hostname},
    )

    # Discovery scoring for EXECUTED files (Python batch)
    if case:
        stats["discovery_flagged"] = _flag_discovery_executed(hostname, client, case)

    stats["executed_shimcache"] = _count(
        client,
        """
        MATCH (h:Host {hostname: $hostname})-[e:EXECUTED {source: 'shimcache'}]->(:File)
        RETURN count(e) AS c
        """,
        {"hostname": hostname},
    )
    stats["executed_prefetch"] = _count(
        client,
        """
        MATCH (h:Host {hostname: $hostname})-[e:EXECUTED {source: 'prefetch'}]->(:File)
        RETURN count(e) AS c
        """,
        {"hostname": hostname},
    )
    stats["bulk_referenced"] = _count(
        client,
        """
        MATCH (h:Host {hostname: $hostname})-[:REFERENCED {source: 'bulk_extractor'}]->()
        RETURN count(*) AS c
        """,
        {"hostname": hostname},
    )
    return stats


def _flag_discovery_executed(hostname: str, client: Neo4jClient, case: CaseManifest) -> int:
    disc = discovery_from_case(case)
    rows = client.query(
        """
        MATCH (h:Host {hostname: $hostname})-[:EXECUTED]->(f:File)
        WHERE f.path IS NOT NULL
        RETURN f.id AS id, f.path AS path
        LIMIT 10000
        """,
        {"hostname": hostname},
    )
    updates: list[dict] = []
    for r in rows:
        path = str(r.get("path") or "")
        norm = normalize_windows_path(path)
        score = match_score(norm or path, case, discovery=disc)
        if score >= 0.4:
            updates.append({"id": r["id"], "score": round(score, 3)})
    for i in range(0, len(updates), 500):
        chunk = updates[i : i + 500]
        client.run(
            """
            UNWIND $rows AS row
            MATCH (f:File {id: row.id})
            SET f.discoveryScore = row.score, f.executionInteresting = true
            """,
            {"rows": chunk},
        )
    return len(updates)


def _count(client: Neo4jClient, cypher: str, params: dict) -> int:
    rows = client.query(cypher, params)
    if not rows:
        return 0
    val = rows[0].get("c")
    return int(val) if val is not None else 0
