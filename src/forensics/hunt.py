"""DFIR hunt queries via Neo4j (runs without GraphQL server)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml

from forensics.neo4j_client import Neo4jClient

_EXCLUSIONS_PATH = Path(__file__).resolve().parents[2] / "config" / "exclusions.yaml"


def load_exclusion_params(hunt_name: str) -> dict[str, list[str]]:
    """Load a hunt's config dictionaries (denylist / patterns / etc.) as lowercased
    lists, keyed exactly as defined under the hunt's section in exclusions.yaml."""
    if not _EXCLUSIONS_PATH.exists():
        return {}
    cfg = yaml.safe_load(_EXCLUSIONS_PATH.read_text()) or {}
    section = cfg.get(hunt_name) or {}
    return {
        key: [str(x).lower() for x in val] for key, val in section.items() if isinstance(val, list)
    }


QUERIES: dict[str, str] = {
    # Per-host counts via independent CALL subqueries — each aggregates one
    # relationship type anchored on h, so there is no cross product between
    # processes/modules/connections/events. The previous form stacked four
    # OPTIONAL MATCH patterns (two of them unanchored, incl. a bare
    # `()-[m:LOADED_MODULE]->()`), producing a Cartesian blow-up that ran ~30min
    # and never returned on a large graph. This form returns in <1s for 7 hosts.
    "summary": """
        MATCH (h:Host)
        CALL (h) {
            MATCH (h)<-[:RAN_ON]-(p:Process) RETURN count(p) AS processes
        }
        CALL (h) {
            MATCH (h)<-[:RAN_ON]-(:Process)-[lm:LOADED_MODULE]->() RETURN count(lm) AS modules
        }
        CALL (h) {
            MATCH (h)<-[:RAN_ON]-(:Process)-[c:CONNECTED_TO]->(:IPAddress)
            RETURN count(c) AS connections
        }
        CALL (h) {
            MATCH (h)<-[:REPORTED]-(e:WindowsEvent) RETURN count(e) AS events
        }
        RETURN h.hostname AS host, processes, modules, connections, events
        ORDER BY host
    """,
    "suspicious_processes": """
        MATCH (p:Process)-[:RAN_ON]->(h:Host)
        WHERE p.name CONTAINS '.exe'
          AND NOT p.name IN ['System', 'Registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
            'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe', 'dwm.exe']
        RETURN p.name AS name, p.pid AS pid, p.id AS id
        ORDER BY p.name
        LIMIT 50
    """,
    "external_connections": """
        MATCH (p:Process)-[c:CONNECTED_TO]->(ip:IPAddress)
        WHERE ip.address <> '' AND NOT ip.address STARTS WITH '10.'
          AND NOT ip.address STARTS WITH '192.168.'
          AND NOT ip.address STARTS WITH '172.16.'
          AND ip.address <> '127.0.0.1'
        RETURN p.name AS process, p.pid AS pid, ip.address AS ip,
               c.foreignPort AS port, c.protocol AS protocol
        ORDER BY ip.address
        LIMIT 50
    """,
    "cloud_sync_connections": """
        MATCH (p:Process)-[c:CONNECTED_TO]->(ip:IPAddress)
        WHERE ip.address <> ''
          AND (
            toLower(p.name) CONTAINS 'onedrive'
            OR toLower(p.name) CONTAINS 'googledrive'
            OR toLower(p.name) CONTAINS 'google drive'
            OR toLower(p.name) CONTAINS 'icloud'
            OR toLower(p.name) CONTAINS 'dropbox'
          )
        RETURN p.name AS process, p.pid AS pid, ip.address AS ip,
               c.foreignPort AS port, c.protocol AS protocol
        LIMIT 50
    """,
    "process_tree": """
        MATCH (parent:Process)-[:SPAWNED]->(child:Process)
        RETURN parent.name AS parent, parent.pid AS parent_pid,
               child.name AS child, child.pid AS child_pid
        LIMIT 30
    """,
    "sensitive_file_touch": """
        MATCH (f:File)
        WHERE f.sensitive = true OR f.type = 'mft' OR f.sensitiveScore >= 0.4
        RETURN f.path AS path, f.name AS name, f.sensitive AS sensitive,
               f.sensitiveScore AS score
        LIMIT 100
    """,
    "after_hours_logons": """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host)
        WHERE e.eventId = 4624 AND e.timestamp IS NOT NULL
        RETURN e.id AS id, e.timestamp AS timestamp, e.targetUser AS target_user,
               h.hostname AS host
        ORDER BY e.timestamp
        LIMIT 100
    """,
    "usb_insertions": """
        MATCH (u:USBDevice)-[:PLUGGED_INTO]->(h:Host)
        RETURN u.id AS id, u.deviceId AS device_id, u.friendlyName AS friendly_name,
               u.vendor AS vendor, u.firstSeen AS first_seen, u.lastSeen AS last_seen,
               h.hostname AS host
        ORDER BY u.lastSeen
        LIMIT 50
    """,
    "photos_outside_home": """
        MATCH (m:MediaAsset)-[:STORED_ON]->(h:Host)
        WHERE m.latitude IS NOT NULL AND m.longitude IS NOT NULL
          AND (abs(m.latitude - $home_lat) > $degree_threshold
               OR abs(m.longitude - $home_lon) > $degree_threshold)
        RETURN m.path AS path, m.takenAt AS taken_at, m.latitude AS lat, m.longitude AS lon,
               h.hostname AS host
        LIMIT 50
    """,
    "photos_during_vacation": """
        MATCH (m:MediaAsset)-[:STORED_ON]->(h:Host)
        WHERE m.takenAt >= $window_start AND m.takenAt < $window_end
        RETURN m.path AS path, m.takenAt AS taken_at, m.latitude AS lat, m.longitude AS lon,
               h.hostname AS host
        ORDER BY m.takenAt
        LIMIT 100
    """,
    "sync_volume_spike": """
        MATCH (m:MediaAsset)-[:STORED_ON]->(h:Host)
        WHERE m.path IS NOT NULL
          AND (toLower(m.path) CONTAINS 'icloud'
               OR toLower(m.path) CONTAINS 'onedrive'
               OR toLower(m.path) CONTAINS 'google')
        WITH substring(m.takenAt, 0, 10) AS day, count(*) AS cnt
        WHERE day <> ''
        RETURN day, cnt
        ORDER BY cnt DESC
        LIMIT 30
    """,
    "sysmon_file_touch": """
        MATCH (e:WindowsEvent)-[:CREATED_FILE|DELETED_FILE]->(f:File)
        WHERE e.eventId IN [11, 23]
        RETURN e.eventId AS event_id, e.timestamp AS timestamp,
               f.path AS path, e.image AS process_image
        ORDER BY e.timestamp
        LIMIT 50
    """,
    "sysmon_process_spawn": """
        MATCH (parent:Process)-[r:SPAWNED {source: 'sysmon'}]->(child:Process)
        RETURN parent.name AS parent, child.name AS child, r.timestamp AS timestamp
        ORDER BY r.timestamp DESC
        LIMIT 40
    """,
    "dns_queries": """
        MATCH (e:WindowsEvent)-[:RESOLVED_DNS]->(d:Domain)
        WHERE e.eventId = 22
        RETURN e.id AS event_id, e.channel AS channel,
               d.name AS domain, e.dnsQuery AS query, e.image AS process_image,
               e.timestamp AS timestamp
        ORDER BY e.timestamp DESC
        LIMIT 50
    """,
    "lateral_logons": """
        MATCH (u:UserAccount)-[l:LOGGED_IN]->(h:Host)
        WHERE l.logonType IN ['3', '10']
        RETURN u.username AS user, l.logonType AS logon_type, l.ip AS ip,
               l.timestamp AS timestamp, h.hostname AS host
        ORDER BY l.timestamp
        LIMIT 50
    """,
    "failed_logons": """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host)
        WHERE e.eventId = 4625
        RETURN e.id AS event_id, e.channel AS channel,
               e.targetUser AS user, e.logonType AS logon_type, e.ip AS ip,
               e.timestamp AS timestamp, h.hostname AS host
        LIMIT 50
    """,
    "registry_persistence": """
        MATCH (p:Process)-[:MODIFIED]->(rk:RegistryKey)
        WHERE toLower(rk.path) CONTAINS 'run'
           OR toLower(rk.path) CONTAINS 'services'
        RETURN p.name AS process, rk.path AS registry_path, rk.details AS details
        LIMIT 40
    """,
    "service_install": """
        MATCH (e:WindowsEvent)-[:INSTALLED_SERVICE]->(s:WindowsService)
        OPTIONAL MATCH (e)-[:REPORTED]->(h:Host)
        RETURN h.hostname AS host, s.name AS service, s.imagePath AS image_path,
               count(e) AS installs
        ORDER BY installs DESC, host, service
        LIMIT 50
    """,
    "log_cleared": """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host)
        WHERE e.eventId = 104
        RETURN e.id AS event_id, e.logChannel AS channel, e.timestamp AS timestamp,
               h.hostname AS host
        LIMIT 20
    """,
    "powershell_script": """
        MATCH (e:WindowsEvent)-[:EXECUTED_SCRIPT]->(sb:ScriptBlock)
        WHERE e.eventId = 4104
        RETURN e.id AS event_id, e.channel AS channel, e.timestamp AS timestamp,
               sb.text AS script_preview, e.image AS process_image
        ORDER BY e.timestamp DESC
        LIMIT 20
    """,
    "event_coverage": """
        MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host)
        RETURN e.eventId AS eventId, e.channel AS channel, count(*) AS cnt
        ORDER BY cnt DESC
        LIMIT 30
    """,
    "findings_summary": """
        MATCH (f:Finding)
        RETURN f.id AS id, f.hypothesisId AS hypothesis, f.verdict AS verdict,
               f.confidence AS confidence, f.stepId AS step_id, f.summary AS summary
        ORDER BY f.stepId
        LIMIT 50
    """,
    "execution_corroboration": """
        MATCH (h:Host)-[ex:EXECUTED]->(f:File)
        WHERE ex.confidence = 'corroborated_sysmon'
           OR (f)<-[:CREATED {source: 'sysmon'}]-(:Process)
           OR (f)<-[:DESCRIBES]-(:WindowsEvent)
        RETURN f.path AS path, ex.source AS execution_source, ex.confidence AS confidence
        LIMIT 50
    """,
    "prefetch_sensitive_paths": """
        MATCH (h:Host)-[ex:EXECUTED {source: 'prefetch'}]->(f:File)
        WHERE f.sensitive = true OR f.sensitiveScore >= 0.4 OR f.executionInteresting = true
        RETURN f.path AS path, f.sensitive AS sensitive, f.sensitiveScore AS score,
               ex.runCount AS run_count, ex.timestamp AS last_run
        ORDER BY f.sensitiveScore DESC
        LIMIT 50
    """,
    "shimcache_staging": """
        MATCH (h:Host)-[ex:EXECUTED {source: 'shimcache'}]->(f:File)
        WHERE f.path IS NOT NULL
          AND (toLower(f.path) CONTAINS 'users'
               OR toLower(f.path) CONTAINS 'design'
               OR toLower(f.path) CONTAINS 'research'
               OR toLower(f.path) CONTAINS 'srl')
        RETURN f.path AS path, ex.timestamp AS timestamp, ex.order AS shim_order
        ORDER BY ex.order DESC
        LIMIT 50
    """,
    "bulk_exfil_signals": """
        MATCH (h:Host)-[:REFERENCED {source: 'bulk_extractor'}]->(x)
        WHERE x:EmailAddress OR x:URL
        RETURN labels(x)[0] AS type,
               coalesce(x.address, x.url) AS value, x.context AS context
        LIMIT 50
    """,
    "bulk_dns_corroboration": """
        MATCH (h:Host)-[:REFERENCED]->(u:URL)-[:SAME_DOMAIN]->(d:Domain)
        MATCH (e:WindowsEvent)-[:RESOLVED_DNS]->(d)
        WHERE e.eventId = 22
        RETURN u.url AS bulk_url, d.name AS domain, e.image AS process_image,
               e.timestamp AS dns_timestamp
        LIMIT 30
    """,
    "psexec_lateral": """
        CALL {
            MATCH (h:Host)-[ex:EXECUTED]->(f:File)
            WHERE toLower(f.name) IN ['psexec.exe', 'psexesvc.exe']
            RETURN f.name AS indicator, h.hostname AS host, ex.source AS evidence,
                   CASE ex.source WHEN 'prefetch' THEN 'high' ELSE 'medium' END AS confidence,
                   count(*) AS observations
            UNION
            MATCH (e:WindowsEvent)-[:INSTALLED_SERVICE]->(s:WindowsService)
            WHERE toLower(s.name) = 'psexec'
               OR toLower(coalesce(s.imagePath, '')) CONTAINS 'psexesvc'
            OPTIONAL MATCH (e)-[:REPORTED]->(h:Host)
            RETURN 'PsExec service' AS indicator, h.hostname AS host,
                   'service_7045' AS evidence, 'high' AS confidence,
                   count(e) AS observations
        }
        RETURN indicator, host, evidence, confidence, observations
        ORDER BY confidence, host, evidence
        LIMIT 100
    """,
    "suspicious_execution_ancestry": """
        // Behavioral pslist-PPID ancestry. Detection is by BEHAVIOR, not name:
        // the only literal name lists are generic-Windows BENIGN baselines
        // (system procs / shell launchers). Attacker binaries are never named.
        MATCH (parent:Process)-[:SPAWNED]->(child:Process)-[:RAN_ON]->(h:Host)
        OPTIONAL MATCH (gp:Process)-[:SPAWNED]->(parent)
        WITH parent, child, h,
             toLower(parent.name) AS pn, toLower(child.name) AS cn,
             toLower(coalesce(gp.name, '')) AS gpn
        WITH parent, child, h, pn, cn, gpn,
             ['system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
              'services.exe', 'lsass.exe', 'lsm.exe', 'svchost.exe', 'explorer.exe',
              'userinit.exe', 'dwm.exe', 'taskhost.exe', 'taskhostw.exe', 'taskeng.exe',
              'spoolsv.exe', 'searchindexer.exe', 'searchprotocolhost.exe', 'wmiprvse.exe',
              'mmc.exe', 'gpscript.exe', 'runonce.exe', 'conhost.exe', 'dllhost.exe'] AS sys,
             ['cmd.exe', 'powershell.exe', 'pwsh.exe'] AS shells,
             ['explorer.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'userinit.exe',
              'mmc.exe', 'services.exe', 'svchost.exe', 'taskeng.exe', 'taskhost.exe',
              'wmiprvse.exe', 'gpscript.exe'] AS benignLaunchers
        WITH parent, child, h, pn, cn, gpn, sys, shells, benignLaunchers,
             (size(replace(pn, '.exe', '')) <= 2) AS shortParent,
             // self-replication, but NOT a service forking its own workers
             // (Apache/snmp/etc spawned by services.exe) which is benign
             (pn = cn AND gpn <> 'services.exe'
              AND NOT pn IN ['svchost.exe', 'dllhost.exe', 'conhost.exe',
                             'wmiprvse.exe', 'taskhostw.exe']) AS selfRep,
             (cn IN shells AND NOT pn IN benignLaunchers) AS shellFromNonSys,
             // a non-system service-launched parent whose child is itself
             // onward-suspicious (self-replicates or spawns a shell). The
             // onward check + (pn<>cn) drops AV services spawning static helpers.
             (gpn = 'services.exe' AND pn <> cn AND NOT pn IN sys AND NOT cn IN sys
              AND NOT cn IN shells
              AND EXISTS {
                  MATCH (child)-[:SPAWNED]->(gc:Process)
                  WHERE toLower(gc.name) = cn
                     OR toLower(gc.name) IN ['cmd.exe', 'powershell.exe', 'pwsh.exe']
              }) AS serviceStub,
             (pn IN shells AND gpn <> '' AND size(replace(gpn, '.exe', '')) <= 2)
                 AS shellLineage
        WITH parent, child, h, shortParent, selfRep, serviceStub, shellLineage,
             shellFromNonSys,
             [x IN [
                CASE WHEN shortParent THEN 'anomalous_short_parent_name' END,
                CASE WHEN selfRep THEN 'self_replicating_process' END,
                CASE WHEN serviceStub THEN 'service_stub_spawned_nonsystem_child' END,
                CASE WHEN shellLineage THEN 'shell_launched_by_anomalous_parent' END,
                CASE WHEN shellFromNonSys THEN 'shell_spawned_by_nonsystem_parent' END
             ] WHERE x IS NOT NULL] AS why,
             (shortParent OR selfRep OR serviceStub OR shellLineage) AS highSig
        WHERE size(why) > 0
        RETURN parent.name + ' (' + toString(parent.pid) + ')' AS parent,
               child.name + ' (' + toString(child.pid) + ')' AS child,
               h.hostname AS host,
               child.createTime AS createTime,
               why,
               'pslist_ppid' AS evidence,
               CASE WHEN highSig THEN 'high' ELSE 'medium' END AS confidence
        ORDER BY confidence, host, createTime
        LIMIT 100
    """,
    "lateral_tool_reuse": """
        // Same binary EXECUTED on >1 host = shared-toolkit / lateral signal.
        // Denylist (OS/AV/VM/IR-responder) and category dictionaries come from
        // config/exclusions.yaml via $denylist / $dual_use / $offensive params.
        MATCH (h:Host)-[ex:EXECUTED]->(f:File)
        WHERE f.name IS NOT NULL
          AND toLower(f.name) ENDS WITH '.exe'
          AND NOT toLower(f.name) IN $denylist
          AND NOT any(p IN $denylist_prefixes WHERE toLower(f.name) STARTS WITH p)
        WITH toLower(f.name) AS indicator,
             collect(DISTINCT h.hostname) AS hosts,
             collect(DISTINCT ex.source) AS sources
        WHERE size(hosts) > 1
        WITH indicator, hosts, sources,
             ('prefetch' IN sources) AS hasPrefetch,
             (indicator IN $offensive) AS isOffensive,
             (indicator IN $dual_use) AS isDualUse
        RETURN indicator,
               size(hosts) AS host_count,
               hosts,
               CASE WHEN hasPrefetch THEN 'prefetch' ELSE 'shimcache' END AS evidence,
               CASE WHEN isOffensive THEN 'offensive'
                    WHEN isDualUse THEN 'dual_use'
                    ELSE 'unknown' END AS category,
               CASE WHEN isDualUse THEN 'medium'
                    WHEN hasPrefetch THEN 'high'
                    ELSE 'medium' END AS confidence
        ORDER BY confidence,
                 CASE WHEN isOffensive THEN 0 WHEN isDualUse THEN 1 ELSE 2 END,
                 host_count DESC, indicator
        LIMIT 100
    """,
    "credential_tooling": """
        // Credential-theft tooling by NAME PATTERN (substring) from
        // config/exclusions.yaml ($patterns). Attribution is name-heuristic /
        // INFERENTIAL — identity inferred from naming, not confirmed.
        MATCH (h:Host)-[ex:EXECUTED]->(f:File)
        WHERE f.name IS NOT NULL
          AND any(p IN $patterns WHERE toLower(f.name) CONTAINS p)
        WITH toLower(f.name) AS indicator, h.hostname AS host,
             collect(DISTINCT ex.source) AS sources,
             head([p IN $patterns WHERE toLower(f.name) CONTAINS p]) AS matched_pattern
        RETURN indicator, host, matched_pattern,
               CASE WHEN 'prefetch' IN sources THEN 'prefetch' ELSE 'shimcache' END AS evidence,
               CASE WHEN 'prefetch' IN sources THEN 'high' ELSE 'medium' END AS confidence,
               'name_heuristic' AS attribution
        ORDER BY confidence, indicator, host
        LIMIT 100
    """,
}

CASE_PARAM_HUNTS = frozenset({"photos_outside_home", "photos_during_vacation"})
EXCLUSION_PARAM_HUNTS = frozenset({"lateral_tool_reuse", "credential_tooling"})


def hunt_parameters_from_case(case) -> dict[str, Any]:
    """Build Cypher parameters for case-aware hunts."""
    media = getattr(case, "media", None) or {}
    if not isinstance(media, dict):
        media = {}
    home = media.get("home_coordinates") or {}
    window = media.get("vacation_window") or getattr(case, "time_window", None) or {}
    return {
        "home_lat": float(home.get("lat", 0)),
        "home_lon": float(home.get("lon", 0)),
        "degree_threshold": float(media.get("gps_degree_threshold", 0.05)),
        "window_start": str(window.get("start", "")),
        "window_end": str(window.get("end", "")),
    }


def run_hunt(
    name: str,
    client: Neo4jClient | None = None,
    *,
    case=None,
) -> dict[str, Any]:
    if name == "path_discover":
        if case is None:
            return {"error": "path_discover requires --case"}
        from forensics.path_discover import run_path_discover

        return run_path_discover(case, client=client)
    if name not in QUERIES:
        return {"error": f"unknown query {name}", "available": list(QUERIES)}
    own = client is None
    c = client or Neo4jClient()
    if name in CASE_PARAM_HUNTS and case:
        params = hunt_parameters_from_case(case)
    elif name in EXCLUSION_PARAM_HUNTS:
        params = load_exclusion_params(name)
    else:
        params = None
    try:
        rows = c.query(QUERIES[name], params)
        return {"query": name, "rows": rows, "parameters": params}
    finally:
        if own:
            c.close()


def main() -> None:
    name = sys.argv[1] if len(sys.argv) > 1 else "summary"
    result = run_hunt(name)
    if "error" in result:
        print(json.dumps(result, indent=2))
        sys.exit(1)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
