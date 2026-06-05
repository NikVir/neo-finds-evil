"""Hunt → artifact dependencies for progressive ingest."""

from __future__ import annotations

from dataclasses import dataclass

from forensics.ingest.tiers import TIER_ORDER, tier_for_artifacts, resolve_tier_plan
from forensics.neo4j_client import Neo4jClient

# required: all must be loaded; any_of: at least one group must be satisfied
HUNT_DEPS: dict[str, dict[str, list[str]]] = {
    "summary": {"required": ["pslist"], "any_of": []},
    "event_coverage": {"required": ["evtx"], "any_of": []},
    "suspicious_processes": {"required": ["pslist"], "any_of": []},
    "external_connections": {"required": [], "any_of": ["netscan", "evtx"]},
    "cloud_sync_connections": {"required": [], "any_of": ["netscan", "evtx"]},
    "process_tree": {"required": ["pslist"], "any_of": ["evtx"]},
    "sensitive_file_touch": {"required": ["path_catalog"], "any_of": ["mft"]},
    "after_hours_logons": {"required": ["evtx"], "any_of": []},
    "usb_insertions": {"required": ["usb"], "any_of": []},
    "photos_outside_home": {"required": ["media_exif"], "any_of": []},
    "photos_during_vacation": {"required": ["media_exif"], "any_of": []},
    "sync_volume_spike": {"required": ["media_exif"], "any_of": []},
    "sysmon_file_touch": {"required": ["evtx"], "any_of": []},
    "sysmon_process_spawn": {"required": ["evtx"], "any_of": []},
    "dns_queries": {"required": ["evtx"], "any_of": []},
    "lateral_logons": {"required": ["evtx"], "any_of": []},
    "failed_logons": {"required": ["evtx"], "any_of": []},
    "registry_persistence": {"required": ["evtx"], "any_of": []},
    "service_install": {"required": ["evtx"], "any_of": []},
    "log_cleared": {"required": ["evtx"], "any_of": []},
    "powershell_script": {"required": ["evtx"], "any_of": []},
    "findings_summary": {"required": [], "any_of": []},
    "execution_corroboration": {
        "required": [],
        "any_of": ["shimcache", "prefetch"],
    },
    "psexec_lateral": {"required": [], "any_of": ["shimcache", "prefetch", "evtx"]},
    "suspicious_execution_ancestry": {"required": ["pslist"], "any_of": []},
    "lateral_tool_reuse": {"required": [], "any_of": ["shimcache", "prefetch"]},
    "credential_tooling": {"required": [], "any_of": ["shimcache", "prefetch"]},
    "prefetch_sensitive_paths": {"required": ["prefetch"], "any_of": []},
    "shimcache_staging": {"required": ["shimcache"], "any_of": []},
    "bulk_exfil_signals": {"required": ["bulk"], "any_of": []},
    "bulk_dns_corroboration": {"required": ["bulk", "evtx"], "any_of": []},
    "path_discover": {"required": [], "any_of": ["path_catalog", "mft"]},
}


@dataclass(frozen=True)
class HuntDepCheck:
    hunt: str
    satisfied: bool
    missing_required: tuple[str, ...]
    missing_any_of: tuple[str, ...]
    minimum_tier: str
    suggested_tier: str
    load_command: str


def _artifacts_for_hunt(hunt: str) -> frozenset[str]:
    deps = HUNT_DEPS.get(hunt, {"required": [], "any_of": []})
    needed: set[str] = set(deps.get("required") or [])
    any_of = deps.get("any_of") or []
    if any_of and not needed.intersection(any_of):
        needed.add(any_of[0])
    return frozenset(needed)


def minimum_tier_for_hunt(hunt: str) -> str:
    return tier_for_artifacts(_artifacts_for_hunt(hunt))


def check_hunt_deps(hunt: str, loaded: set[str], *, hostname: str = "HOST") -> HuntDepCheck:
    deps = HUNT_DEPS.get(hunt)
    if not deps:
        return HuntDepCheck(
            hunt=hunt,
            satisfied=True,
            missing_required=(),
            missing_any_of=(),
            minimum_tier="triage",
            suggested_tier="triage",
            load_command="",
        )
    required = [a for a in deps.get("required") or [] if a not in loaded]
    any_of = deps.get("any_of") or []
    missing_any: list[str] = []
    if any_of and not any(a in loaded for a in any_of):
        missing_any = list(any_of)
    satisfied = not required and not missing_any
    needed = set(required) | (set(missing_any[:1]) if missing_any else set())
    min_tier = tier_for_artifacts(frozenset(needed)) if needed else "triage"
    suggested = min_tier
    load_cmd = ""
    if not satisfied:
        load_cmd = (
            f"uv run forensics-ingest load-tier {suggested} "
            f"-m config/hosts/<host>.yaml -c config/cases/<case>.yaml"
        ).replace("<host>", hostname)
    return HuntDepCheck(
        hunt=hunt,
        satisfied=satisfied,
        missing_required=tuple(required),
        missing_any_of=tuple(missing_any),
        minimum_tier=min_tier,
        suggested_tier=suggested,
        load_command=load_cmd,
    )


def artifacts_loaded(client: Neo4jClient, hostname: str) -> set[str]:
    loaded: set[str] = set()
    if client.host_has_events(hostname):
        loaded.add("evtx")
    checks = [
        (
            "pslist",
            """
            MATCH (p:Process)-[:RAN_ON]->(h:Host {hostname: $hostname})
            RETURN count(p) AS c LIMIT 1
            """,
        ),
        (
            "netscan",
            """
            MATCH (p:Process)-[:CONNECTED_TO]->(:IPAddress)
            WHERE p.id STARTS WITH $hostname + ':'
            RETURN count(*) AS c LIMIT 1
            """,
        ),
        (
            "dlllist",
            """
            MATCH (p:Process)-[:LOADED_MODULE]->(:File)
            WHERE p.id STARTS WITH $hostname + ':'
            RETURN count(*) AS c LIMIT 1
            """,
        ),
        (
            "shimcache",
            """
            MATCH (h:Host {hostname: $hostname})-[ex:EXECUTED {source: 'shimcache'}]->()
            RETURN count(ex) AS c LIMIT 1
            """,
        ),
        (
            "prefetch",
            """
            MATCH (h:Host {hostname: $hostname})-[ex:EXECUTED {source: 'prefetch'}]->()
            RETURN count(ex) AS c LIMIT 1
            """,
        ),
        (
            "path_catalog",
            """
            MATCH (f:File {source: 'filestat'})-[:ON_HOST]->(h:Host {hostname: $hostname})
            RETURN count(f) AS c LIMIT 1
            """,
        ),
        (
            "mft",
            """
            MATCH (f:File {type: 'mft'})-[:ON_HOST]->(h:Host {hostname: $hostname})
            RETURN count(f) AS c LIMIT 1
            """,
        ),
        (
            "media_exif",
            """
            MATCH (m:MediaAsset)-[:STORED_ON]->(h:Host {hostname: $hostname})
            RETURN count(m) AS c LIMIT 1
            """,
        ),
        (
            "usb",
            """
            MATCH (u:USBDevice)-[:PLUGGED_INTO]->(h:Host {hostname: $hostname})
            RETURN count(u) AS c LIMIT 1
            """,
        ),
        (
            "bulk",
            """
            MATCH (h:Host {hostname: $hostname})-[:REFERENCED {source: 'bulk_extractor'}]->()
            RETURN count(*) AS c LIMIT 1
            """,
        ),
    ]
    for name, cypher in checks:
        if name in loaded:
            continue
        rows = client.query(cypher, {"hostname": hostname})
        if rows and int(rows[0].get("c") or 0) > 0:
            loaded.add(name)
    return loaded


def build_ingest_plan(
    case_type: str,
    hostnames: list[str],
    client: Neo4jClient,
    *,
    hunt: str | None = None,
) -> dict:
    hosts_out = []
    for hostname in hostnames:
        loaded = artifacts_loaded(client, hostname)
        triage = resolve_tier_plan("triage", case_type)
        full = resolve_tier_plan("full", case_type)
        hosts_out.append(
            {
                "hostname": hostname,
                "loaded": sorted(loaded),
                "triage_artifacts": sorted(triage.artifacts),
                "missing_for_triage": sorted(triage.artifacts - loaded),
                "available_not_loaded": sorted(full.artifacts - loaded),
            }
        )
    out: dict = {"case_type": case_type, "tiers": list(TIER_ORDER), "hosts": hosts_out}
    if hunt:
        checks = [check_hunt_deps(hunt, artifacts_loaded(client, h), hostname=h) for h in hostnames]
        out["hunt"] = hunt
        out["hunt_checks"] = [
            {
                "hostname": hostnames[i],
                "satisfied": c.satisfied,
                "missing_required": list(c.missing_required),
                "missing_any_of": list(c.missing_any_of),
                "suggested_tier": c.suggested_tier,
                "load_command": c.load_command,
            }
            for i, c in enumerate(checks)
        ]
    return out
