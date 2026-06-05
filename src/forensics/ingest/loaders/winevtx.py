"""Ingest Plaso winevtx JSONL -> WindowsEvent and related nodes (profile-driven)."""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET

from forensics.cache import IngestCache, stream_ndjson
from forensics.case import CaseManifest
from forensics.event_profile import (
    EventProfile,
    allowed_eids_for_packs,
    load_profile,
    profile_for_case_type,
)
from forensics.ingest.dedup import DedupRule, EventDeduplicator, resolve_dedup_rules
from forensics.ingest.loaders.base import OptionalLoader
from forensics.normalize import normalize_record
from forensics.timestamps import normalize_timestamp

_SCRIPT_TRUNC = 2000


def _event_id_from_record(raw: dict) -> int | None:
    eid = raw.get("event_id") or raw.get("event_identifier")
    if eid is not None:
        try:
            return int(eid)
        except (TypeError, ValueError):
            pass
    xml_str = raw.get("xml_string") or ""
    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml_str)
    return int(m.group(1)) if m else None


def _stable_event_id(hostname: str, raw: dict) -> str:
    uuid = raw.get("uuid") or raw.get("record_number") or ""
    if uuid:
        return f"{hostname}:{uuid}"
    ts = str(raw.get("datetime") or raw.get("timestamp") or "")
    key = f"{hostname}:{ts}:{raw.get('event_id', '')}"
    return f"{hostname}:{hashlib.sha256(key.encode()).hexdigest()[:16]}"


def _parse_event_xml(xml_str: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not xml_str:
        return out
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return out
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    for data in root.findall(".//e:EventData/e:Data", ns):
        name = data.get("Name")
        if name and data.text:
            out[name] = data.text.strip()
    return out


def _field(fields: dict[str, str], *keys: str) -> str:
    for k in keys:
        if fields.get(k):
            return str(fields[k])
    return ""


def _truncate(s: str, n: int = _SCRIPT_TRUNC) -> str:
    return s[:n] if len(s) > n else s


def _basename(path: str) -> str:
    """Last path component of a Windows or POSIX path; '' for empty."""
    if not path:
        return ""
    return re.split(r"[\\/]", path)[-1]


def _to_int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _skip_addr(addr: str) -> bool:
    """Skip wildcard / loopback / null destinations (mirrors netscan)."""
    if not addr or addr in ("0.0.0.0", "0.0.0.0:0", "*", "-"):
        return True
    return addr.startswith("127.") or addr == "::1"


# --- Pure projection row-shapers -------------------------------------------
# Each takes the cached event batch and returns the rows for one relationship
# projection. Filtering/keying lives here (pure, unit-tested); the Cypher that
# consumes these rows is a thin UNWIND/MERGE.


def sysmon_spawn_rows(batch: list[dict]) -> list[dict]:
    """SPAWNED{source:'sysmon'}: Sysmon EID 1 parentProcessGuid -> processGuid."""
    out: list[dict] = []
    for r in batch:
        if r.get("event_id") != 1:
            continue
        child_guid = r.get("process_guid") or ""
        parent_guid = r.get("parent_process_guid") or ""
        if not child_guid or not parent_guid:
            continue
        host = r["hostname"]
        out.append(
            {
                "hostname": host,
                "parent_id": f"{host}:guid:{parent_guid}",
                "parent_name": _basename(r.get("parent_image") or ""),
                "child_id": f"{host}:guid:{child_guid}",
                "child_name": _basename(r.get("image") or ""),
                "child_pid": _to_int(r.get("process_id")),
                "timestamp": r.get("timestamp"),
            }
        )
    return out


def sysmon_connection_rows(batch: list[dict]) -> list[dict]:
    """CONNECTED_TO: Sysmon EID 3 process -> IPAddress (destination)."""
    out: list[dict] = []
    for r in batch:
        if r.get("event_id") != 3:
            continue
        guid = r.get("process_guid") or ""
        address = r.get("ip") or ""
        if not guid or _skip_addr(address):
            continue
        host = r["hostname"]
        out.append(
            {
                "hostname": host,
                "proc_id": f"{host}:guid:{guid}",
                "proc_name": _basename(r.get("image") or ""),
                "pid": _to_int(r.get("process_id")),
                "address": address,
                "port": _to_int(r.get("port")),
                "protocol": r.get("protocol") or "",
                "timestamp": r.get("timestamp"),
            }
        )
    return out


def sysmon_registry_rows(batch: list[dict]) -> list[dict]:
    """MODIFIED: Sysmon EID 12/13 process -> RegistryKey."""
    out: list[dict] = []
    for r in batch:
        if r.get("event_id") not in (12, 13):
            continue
        guid = r.get("process_guid") or ""
        key = r.get("registry_key") or ""
        if not guid or not key:
            continue
        host = r["hostname"]
        out.append(
            {
                "hostname": host,
                "proc_id": f"{host}:guid:{guid}",
                "proc_name": _basename(r.get("image") or ""),
                "pid": _to_int(r.get("process_id")),
                "registry_id": f"{host}:{key}",
                "registry_key": key,
                "registry_details": r.get("registry_details") or "",
                "timestamp": r.get("timestamp"),
            }
        )
    return out


def sysmon_file_rows(batch: list[dict]) -> list[dict]:
    """CREATED_FILE/DELETED_FILE: Sysmon EID 11 (create) / 23 (delete) -> File."""
    out: list[dict] = []
    for r in batch:
        eid = r.get("event_id")
        if eid not in (11, 23):
            continue
        path = r.get("target_filename") or ""
        if not path:
            continue
        host = r["hostname"]
        out.append(
            {
                "event_node_id": r["id"],
                "hostname": host,
                "file_id": f"{host}:{path}",
                "path": path,
                "name": _basename(path),
                "deleted": eid == 23,
            }
        )
    return out


def logon_rows(batch: list[dict]) -> list[dict]:
    """LOGGED_IN: 4624 UserAccount -> Host, carrying logonType + ip."""
    out: list[dict] = []
    for r in batch:
        if r.get("event_id") != 4624:
            continue
        user = r.get("target_user") or ""
        if not user:
            continue
        out.append(
            {
                "hostname": r["hostname"],
                "user": user,
                "timestamp": r.get("timestamp"),
                "logon_type": r.get("logon_type") or "",
                "ip": r.get("ip") or "",
            }
        )
    return out


class WinevtxLoader(OptionalLoader):
    name = "evtx"
    _case: CaseManifest | None = None
    _event_profile: EventProfile | None = None
    _evtx_packs: frozenset[str] | None = None
    dedup_stats: list[dict] | None = None

    def set_evtx_packs(self, packs: frozenset[str] | None) -> None:
        self._evtx_packs = packs

    def set_case(self, case: CaseManifest) -> None:
        self._case = case
        self._event_profile = None

    def get_dedup_rules(self) -> list[DedupRule]:
        config = getattr(self._case, "evtx_dedup", None) if self._case else None
        return resolve_dedup_rules(config)

    def get_profile(self) -> EventProfile:
        if self._event_profile is None:
            if self.manifest.event_profile:
                self._event_profile = load_profile(self.manifest.event_profile)
            elif self._case is not None:
                self._event_profile = profile_for_case_type(self._case.case_type)
            else:
                self._event_profile = profile_for_case_type("base_windows")
        return self._event_profile

    def load(self) -> int:
        profile = self.get_profile()
        eids = allowed_eids_for_packs(profile, self._evtx_packs)
        path = self.path()
        spill = self.manifest.spill_dir or self.manifest.data_dir / ".ingest_cache"
        cache = IngestCache(spill, self.hostname, "evtx")
        # First-occurrence-per-tuple collapse for high-volume classes (4624,
        # EID 3, ...). Applied in stream order so "first" is deterministic;
        # non-deduplicated classes are passed through untouched. See
        # forensics.ingest.dedup for the rationale.
        dedup = EventDeduplicator(self.get_dedup_rules())
        count = 0

        for raw in stream_ndjson(path, normalize_record):
            eid = _event_id_from_record(raw)
            if eid is None or eid not in eids:
                continue
            xml_str = raw.get("xml_string") or raw.get("message") or ""
            fields = _parse_event_xml(xml_str)
            event_node_id = _stable_event_id(self.hostname, raw)
            ts = normalize_timestamp(raw.get("datetime") or raw.get("date_time") or "")

            row = {
                "id": event_node_id,
                "hostname": self.hostname,
                "event_id": eid,
                "timestamp": ts,
                "channel": raw.get("source") or raw.get("display_name") or "",
                "computer": _field(fields, "Computer") or self.hostname,
                "image": _field(fields, "Image", "NewProcessName", "ProcessName"),
                "command_line": _field(fields, "CommandLine"),
                "parent_image": _field(fields, "ParentImage", "ParentProcessName"),
                "target_filename": _field(fields, "TargetFilename"),
                "parent_pid": _field(fields, "ParentProcessId"),
                "process_id": _field(fields, "ProcessId"),
                "process_guid": _field(fields, "ProcessGuid"),
                "parent_process_guid": _field(fields, "ParentProcessGuid"),
                "target_user": _field(fields, "TargetUserName", "SubjectUserName", "AccountName"),
                "logon_type": _field(fields, "LogonType"),
                "workstation": _field(fields, "WorkstationName", "Workstation"),
                "ip": _field(
                    fields,
                    "DestinationIp",
                    "IpAddress",
                    "SourceNetworkAddress",
                ),
                "port": _field(fields, "DestinationPort"),
                "protocol": _field(fields, "Protocol"),
                "hashes": _field(fields, "Hashes"),
                "dns_query": _field(fields, "QueryName"),
                "registry_key": _field(fields, "TargetObject"),
                "registry_details": _field(fields, "Details"),
                "image_loaded": _field(fields, "ImageLoaded"),
                "service_name": _field(fields, "ServiceName"),
                "service_path": _field(fields, "ImagePath"),
                "script_block": _truncate(_field(fields, "ScriptBlockText")),
                "log_channel": _field(fields, "Channel"),
                "member_name": _field(fields, "MemberName"),
                "failure_reason": _field(fields, "FailureReason"),
                "consumer": _field(fields, "Consumer"),
                "filter": _field(fields, "Filter"),
            }
            # Collapse high-volume repeats in stream order (deterministic
            # first-seen); non-deduplicated classes always pass through.
            if not dedup.keep(row):
                continue
            cache.add(row)
            count += 1

        self.dedup_stats = dedup.stats() or None
        cache.flush()
        for batch in cache.iter_batches():
            self._ingest_events(batch)
            self._ingest_domains(batch)
            self._ingest_registry(batch)
            self._ingest_services(batch)
            self._ingest_scripts(batch)
            self._ingest_wmi(batch)
            self._ingest_logons(batch)
            self._ingest_sysmon_spawn(batch)
            self._ingest_connections(batch)
            self._ingest_modified_registry(batch)
            self._ingest_file_touch(batch)

        return count

    def _ingest_events(self, batch: list) -> None:
        self.client.run_batched(
            """
            UNWIND $rows AS r
            MERGE (h:Host {hostname: r.hostname})
            MERGE (e:WindowsEvent {id: r.id})
            SET e.eventId = r.event_id, e.timestamp = r.timestamp,
                e.channel = r.channel, e.computer = r.computer,
                e.commandLine = r.command_line, e.image = r.image,
                e.targetUser = r.target_user, e.targetFilename = r.target_filename,
                e.processGuid = r.process_guid, e.parentProcessGuid = r.parent_process_guid,
                e.parentImage = r.parent_image,
                e.processId = CASE WHEN r.process_id IS NOT NULL AND r.process_id <> ''
                    THEN toInteger(r.process_id) ELSE null END,
                e.logonType = r.logon_type, e.ip = r.ip, e.port = r.port,
                e.hashes = r.hashes, e.dnsQuery = r.dns_query,
                e.registryKey = r.registry_key, e.imageLoaded = r.image_loaded,
                e.serviceName = r.service_name, e.workstation = r.workstation,
                e.scriptBlock = r.script_block, e.logChannel = r.log_channel
            MERGE (e)-[:REPORTED]->(h)
            """,
            batch,
        )

    def _ingest_logons(self, batch: list) -> None:
        # 4624 -> UserAccount-[:LOGGED_IN {logonType, ip, timestamp}]->Host.
        # logonType/ip are required by the lateral_logons hunt's WHERE filter.
        rows = logon_rows(batch)
        self.client.run_batched(
            """
            UNWIND $rows AS r
            MERGE (h:Host {hostname: r.hostname})
            MERGE (u:UserAccount {sid: r.hostname + ':' + r.user})
            SET u.username = r.user
            MERGE (u)-[l:LOGGED_IN {timestamp: r.timestamp}]->(h)
            SET l.logonType = r.logon_type, l.ip = r.ip
            """,
            rows,
        )

    def _ingest_sysmon_spawn(self, batch: list) -> None:
        # Sysmon EID 1 -> Process-[:SPAWNED {source:'sysmon'}]->Process.
        rows = sysmon_spawn_rows(batch)
        self.client.run_batched(
            """
            UNWIND $rows AS r
            MERGE (h:Host {hostname: r.hostname})
            MERGE (parent:Process {id: r.parent_id})
              ON CREATE SET parent.name = r.parent_name, parent.source = 'sysmon'
            SET parent.name = coalesce(parent.name, r.parent_name)
            MERGE (child:Process {id: r.child_id})
              ON CREATE SET child.name = r.child_name, child.pid = r.child_pid,
                            child.source = 'sysmon'
            SET child.name = coalesce(child.name, r.child_name),
                child.pid = coalesce(child.pid, r.child_pid)
            MERGE (parent)-[:RAN_ON]->(h)
            MERGE (child)-[:RAN_ON]->(h)
            MERGE (parent)-[s:SPAWNED {source: 'sysmon'}]->(child)
            SET s.timestamp = r.timestamp, s.confidence = 'observed'
            """,
            rows,
        )

    def _ingest_connections(self, batch: list) -> None:
        # Sysmon EID 3 -> Process-[:CONNECTED_TO {source:'sysmon'}]->IPAddress.
        rows = sysmon_connection_rows(batch)
        self.client.run_batched(
            """
            UNWIND $rows AS r
            MERGE (h:Host {hostname: r.hostname})
            MERGE (p:Process {id: r.proc_id})
              ON CREATE SET p.name = r.proc_name, p.pid = r.pid, p.source = 'sysmon'
            SET p.name = coalesce(p.name, r.proc_name), p.pid = coalesce(p.pid, r.pid)
            MERGE (p)-[:RAN_ON]->(h)
            MERGE (ip:IPAddress {address: r.address})
              ON CREATE SET ip.id = r.address
            MERGE (p)-[c:CONNECTED_TO]->(ip)
            SET c.foreignPort = r.port, c.protocol = r.protocol,
                c.source = 'sysmon', c.timestamp = r.timestamp
            """,
            rows,
        )

    def _ingest_modified_registry(self, batch: list) -> None:
        # Sysmon EID 12/13 -> Process-[:MODIFIED {source:'sysmon'}]->RegistryKey.
        # Shares the RegistryKey node id used by _ingest_registry (host:key).
        rows = sysmon_registry_rows(batch)
        self.client.run_batched(
            """
            UNWIND $rows AS r
            MERGE (h:Host {hostname: r.hostname})
            MERGE (p:Process {id: r.proc_id})
              ON CREATE SET p.name = r.proc_name, p.pid = r.pid, p.source = 'sysmon'
            SET p.name = coalesce(p.name, r.proc_name)
            MERGE (p)-[:RAN_ON]->(h)
            MERGE (rk:RegistryKey {id: r.registry_id})
              ON CREATE SET rk.path = r.registry_key
            SET rk.path = coalesce(rk.path, r.registry_key),
                rk.details = coalesce(rk.details, r.registry_details)
            MERGE (p)-[m:MODIFIED]->(rk)
            SET m.source = 'sysmon', m.timestamp = r.timestamp
            """,
            rows,
        )

    def _ingest_file_touch(self, batch: list) -> None:
        # Sysmon EID 11/23 -> WindowsEvent-[:CREATED_FILE|DELETED_FILE]->File.
        rows = sysmon_file_rows(batch)
        created = [r for r in rows if not r["deleted"]]
        deleted = [r for r in rows if r["deleted"]]
        if created:
            self.client.run_batched(self._file_touch_cypher("CREATED_FILE"), created)
        if deleted:
            self.client.run_batched(self._file_touch_cypher("DELETED_FILE"), deleted)

    @staticmethod
    def _file_touch_cypher(rel: str) -> str:
        # rel is a fixed internal literal ('CREATED_FILE' / 'DELETED_FILE'),
        # never user input — Cypher cannot parameterize relationship types.
        return f"""
            UNWIND $rows AS r
            MATCH (e:WindowsEvent {{id: r.event_node_id}})
            MERGE (f:File {{id: r.file_id}})
              ON CREATE SET f.path = r.path, f.name = r.name, f.source = 'sysmon'
            SET f.path = coalesce(f.path, r.path), f.name = coalesce(f.name, r.name)
            MERGE (e)-[:{rel}]->(f)
            """

    def _ingest_domains(self, batch: list) -> None:
        self.client.run_batched(
            """
            UNWIND $rows AS r
            WITH r WHERE r.event_id = 22 AND r.dns_query <> ''
            MATCH (e:WindowsEvent {id: r.id})
            MERGE (d:Domain {name: toLower(r.dns_query)})
            SET d.query = r.dns_query
            MERGE (e)-[:RESOLVED_DNS]->(d)
            """,
            batch,
        )

    def _ingest_registry(self, batch: list) -> None:
        self.client.run_batched(
            """
            UNWIND $rows AS r
            WITH r WHERE r.event_id IN [12, 13, 14] AND r.registry_key <> ''
            MATCH (e:WindowsEvent {id: r.id})
            MERGE (rk:RegistryKey {id: r.hostname + ':' + r.registry_key})
            SET rk.path = r.registry_key, rk.details = r.registry_details
            MERGE (e)-[:MODIFIED_REGISTRY]->(rk)
            """,
            batch,
        )

    def _ingest_services(self, batch: list) -> None:
        self.client.run_batched(
            """
            UNWIND $rows AS r
            WITH r WHERE r.event_id = 7045 AND r.service_name <> ''
            MATCH (e:WindowsEvent {id: r.id})
            MERGE (s:WindowsService {id: r.hostname + ':svc:' + r.service_name})
            SET s.name = r.service_name, s.imagePath = r.service_path
            MERGE (e)-[:INSTALLED_SERVICE]->(s)
            """,
            batch,
        )

    def _ingest_scripts(self, batch: list) -> None:
        self.client.run_batched(
            """
            UNWIND $rows AS r
            WITH r WHERE r.event_id = 4104 AND r.script_block <> ''
            MATCH (e:WindowsEvent {id: r.id})
            MERGE (sb:ScriptBlock {id: r.id + ':sb'})
            SET sb.text = r.script_block, sb.timestamp = r.timestamp
            MERGE (e)-[:EXECUTED_SCRIPT]->(sb)
            """,
            batch,
        )

    def _ingest_wmi(self, batch: list) -> None:
        self.client.run_batched(
            """
            UNWIND $rows AS r
            WITH r WHERE r.event_id = 5861
            MATCH (e:WindowsEvent {id: r.id})
            MERGE (w:WmiBinding {id: r.id + ':wmi'})
            SET w.consumer = r.consumer, w.filter = r.filter
            MERGE (e)-[:WMI_ACTIVITY]->(w)
            """,
            batch,
        )
