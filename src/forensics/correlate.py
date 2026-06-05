"""Post-ingest EVTX correlation: ProcessGuid joins, typed edges."""

from __future__ import annotations

from typing import Any

from forensics.neo4j_client import Neo4jClient


def run_correlation(hostname: str, client: Neo4jClient) -> dict[str, Any]:
    """Build graph edges from WindowsEvent properties after EVTX ingest."""
    stats: dict[str, int] = {}

    # Sysmon EID 1: parent -> child SPAWNED via ProcessGuid stubs
    client.run(
        """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $hostname})
        WHERE e.eventId = 1 AND e.processGuid IS NOT NULL AND e.parentProcessGuid IS NOT NULL
        MERGE (child:Process {id: $hostname + ':guid:' + e.processGuid})
        ON CREATE SET child.name = e.image, child.source = 'sysmon_guid', child.pid = e.processId
        MERGE (parent:Process {id: $hostname + ':guid:' + e.parentProcessGuid})
        ON CREATE SET parent.name = e.parentImage, parent.source = 'sysmon_guid'
        MERGE (parent)-[r:SPAWNED {source: 'sysmon', timestamp: e.timestamp}]->(child)
        """,
        {"hostname": hostname},
    )
    stats["spawned_sysmon"] = _count(
        client,
        """
        MATCH (p:Process)-[r:SPAWNED {source: 'sysmon'}]->(:Process)
        WHERE p.id STARTS WITH $hostname + ':'
        RETURN count(r) AS c
        """,
        {"hostname": hostname},
    )

    # Link Sysmon guid Process to Volatility Process by pid + hostname prefix
    client.run(
        """
        MATCH (sg:Process)
        WHERE sg.id STARTS WITH $hostname + ':guid:' AND sg.pid IS NOT NULL
        MATCH (vp:Process)-[:RAN_ON]->(h:Host {hostname: $hostname})
        WHERE vp.pid = sg.pid AND vp.id STARTS WITH $hostname + ':'
        WITH sg, head(collect(vp)) AS vp
        MERGE (sg)-[:SAME_AS]->(vp)
        """,
        {"hostname": hostname},
    )

    # EID 3: Process -> IP CONNECTED_TO
    client.run(
        """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $hostname})
        WHERE e.eventId = 3 AND e.processGuid IS NOT NULL
          AND e.ip IS NOT NULL AND e.ip <> '' AND e.ip <> '-'
        MERGE (p:Process {id: $hostname + ':guid:' + e.processGuid})
        MERGE (ip:IPAddress {address: e.ip})
        MERGE (p)-[c:CONNECTED_TO {source: 'sysmon', port: e.port, timestamp: e.timestamp}]->(ip)
        """,
        {"hostname": hostname},
    )
    stats["connected_sysmon"] = _count(
        client,
        """
        MATCH (p:Process)-[c:CONNECTED_TO {source: 'sysmon'}]->(:IPAddress)
        WHERE p.id STARTS WITH $hostname + ':guid:'
        RETURN count(c) AS c
        """,
        {"hostname": hostname},
    )

    # EID 11: CREATED file
    client.run(
        """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $hostname})
        WHERE e.eventId = 11 AND e.targetFilename <> ''
        MERGE (f:File {id: $hostname + ':' + e.targetFilename})
        SET f.path = e.targetFilename, f.source = 'sysmon'
        WITH e, f
        OPTIONAL MATCH (p:Process {id: $hostname + ':guid:' + e.processGuid})
        FOREACH (_ IN CASE WHEN p IS NOT NULL THEN [1] ELSE [] END |
            MERGE (p)-[r:CREATED {timestamp: e.timestamp, source: 'sysmon'}]->(f))
        MERGE (e)-[:CREATED_FILE]->(f)
        """,
        {"hostname": hostname},
    )

    # EID 23: DELETED file
    client.run(
        """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $hostname})
        WHERE e.eventId = 23 AND e.targetFilename <> ''
        MERGE (f:File {id: $hostname + ':' + e.targetFilename})
        SET f.path = e.targetFilename
        WITH e, f
        OPTIONAL MATCH (p:Process {id: $hostname + ':guid:' + e.processGuid})
        FOREACH (_ IN CASE WHEN p IS NOT NULL THEN [1] ELSE [] END |
            MERGE (p)-[r:DELETED {timestamp: e.timestamp, source: 'sysmon'}]->(f))
        MERGE (e)-[:DELETED_FILE]->(f)
        """,
        {"hostname": hostname},
    )

    # EID 7: LOADED_MODULE
    client.run(
        """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $hostname})
        WHERE e.eventId = 7 AND e.imageLoaded <> ''
        MERGE (f:File {id: $hostname + ':' + e.imageLoaded})
        SET f.path = e.imageLoaded, f.type = 'dll'
        WITH e, f
        OPTIONAL MATCH (p:Process {id: $hostname + ':guid:' + e.processGuid})
        FOREACH (_ IN CASE WHEN p IS NOT NULL THEN [1] ELSE [] END |
            MERGE (p)-[:LOADED_MODULE {source: 'sysmon'}]->(f))
        """,
        {"hostname": hostname},
    )

    # EID 22: RESOLVED domain (already linked at ingest; ensure Process edge)
    client.run(
        """
        MATCH (e:WindowsEvent)-[:RESOLVED_DNS]->(d:Domain)
        WHERE e.processGuid IS NOT NULL
        MATCH (h:Host {hostname: $hostname})<-[:REPORTED]-(e)
        MERGE (p:Process {id: $hostname + ':guid:' + e.processGuid})
        MERGE (p)-[:RESOLVED {timestamp: e.timestamp}]->(d)
        """,
        {"hostname": hostname},
    )

    # EID 12/13/14: MODIFIED registry
    client.run(
        """
        MATCH (e:WindowsEvent)-[:MODIFIED_REGISTRY]->(rk:RegistryKey)
        WHERE e.processGuid IS NOT NULL
        MATCH (h:Host {hostname: $hostname})<-[:REPORTED]-(e)
        MERGE (p:Process {id: $hostname + ':guid:' + e.processGuid})
        MERGE (p)-[:MODIFIED {timestamp: e.timestamp, eventId: e.eventId}]->(rk)
        """,
        {"hostname": hostname},
    )

    # 4624: LOGGED_IN with logon type and IP
    client.run(
        """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $hostname})
        WHERE e.eventId = 4624 AND e.targetUser <> ''
        MERGE (u:UserAccount {sid: $hostname + ':' + e.targetUser})
        SET u.username = e.targetUser
        MERGE (u)-[l:LOGGED_IN {
            timestamp: e.timestamp,
            logonType: e.logonType,
            ip: e.ip,
            workstation: e.workstation
        }]->(h)
        """,
        {"hostname": hostname},
    )

    # 7045: service on host
    client.run(
        """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $hostname})
        WHERE e.eventId = 7045 AND e.serviceName <> ''
        MATCH (e)-[:INSTALLED_SERVICE]->(s:WindowsService)
        MERGE (h)-[:HAS_SERVICE]->(s)
        """,
        {"hostname": hostname},
    )

    # 4104: script block to process
    client.run(
        """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $hostname})
        WHERE e.eventId = 4104
        MATCH (e)-[:EXECUTED_SCRIPT]->(sb:ScriptBlock)
        OPTIONAL MATCH (p:Process {id: $hostname + ':guid:' + e.processGuid})
        FOREACH (_ IN CASE WHEN p IS NOT NULL THEN [1] ELSE [] END |
            MERGE (p)-[:EXECUTED_SCRIPT {timestamp: e.timestamp}]->(sb))
        """,
        {"hostname": hostname},
    )

    return {"hostname": hostname, "correlation": stats}


def _count(client: Neo4jClient, cypher: str, params: dict | None = None) -> int:
    rows = client.query(cypher, params or {})
    return int(rows[0].get("c", 0)) if rows else 0
