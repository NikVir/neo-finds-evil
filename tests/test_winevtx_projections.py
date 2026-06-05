"""Unit tests for the Sysmon/4624 relationship projections in WinevtxLoader.

These cover the five edges that the corresponding hunts traverse:
  - SPAWNED{source:'sysmon'}  (sysmon_process_spawn)
  - CONNECTED_TO              (external_connections)
  - LOGGED_IN{logonType,ip}   (lateral_logons)
  - MODIFIED                  (registry_persistence)
  - CREATED_FILE/DELETED_FILE (sysmon_file_touch)

The row-shapers are pure functions (filtering/keying), tested directly. The
loader methods are driven with a fake client that records the Cypher + rows,
so we assert both the relationship emitted and that rows are pre-filtered.
"""

from __future__ import annotations

from forensics.ingest.loaders.winevtx import (
    WinevtxLoader,
    _basename,
    logon_rows,
    sysmon_connection_rows,
    sysmon_file_rows,
    sysmon_registry_rows,
    sysmon_spawn_rows,
)


class FakeClient:
    """Records run_batched(query, rows) calls without touching Neo4j."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[dict]]] = []

    def run_batched(self, query, rows, param_key="rows"):  # noqa: ARG002
        self.calls.append((query, list(rows)))
        return len(rows)


def _loader() -> tuple[WinevtxLoader, FakeClient]:
    loader = WinevtxLoader.__new__(WinevtxLoader)
    client = FakeClient()
    loader.client = client
    return loader, client


def _ev(**kw) -> dict:
    base = {
        "id": "h:1",
        "hostname": "HOST",
        "event_id": 0,
        "timestamp": "2018-08-31T00:00:00Z",
        "image": "",
        "parent_image": "",
        "process_guid": "",
        "parent_process_guid": "",
        "process_id": "",
        "target_user": "",
        "logon_type": "",
        "ip": "",
        "port": "",
        "protocol": "",
        "registry_key": "",
        "registry_details": "",
        "target_filename": "",
    }
    base.update(kw)
    return base


# --- _basename --------------------------------------------------------------


def test_basename_windows_posix_empty():
    assert _basename(r"C:\Windows\Temp\perfmon\PsExec.exe") == "PsExec.exe"
    assert _basename("/usr/bin/python3") == "python3"
    assert _basename("bare.exe") == "bare.exe"
    assert _basename("") == ""


# --- SPAWNED (Sysmon EID 1) -------------------------------------------------


def test_spawn_rows_basic_keys_and_names():
    batch = [
        _ev(
            event_id=1,
            image=r"C:\Windows\System32\cmd.exe",
            parent_image=r"C:\Temp\a.exe",
            process_guid="{GUID-C}",
            parent_process_guid="{GUID-P}",
            process_id="3472",
        )
    ]
    rows = sysmon_spawn_rows(batch)
    assert len(rows) == 1
    r = rows[0]
    assert r["parent_id"] == "HOST:guid:{GUID-P}"
    assert r["child_id"] == "HOST:guid:{GUID-C}"
    assert r["parent_name"] == "a.exe"
    assert r["child_name"] == "cmd.exe"
    assert r["child_pid"] == 3472


def test_spawn_rows_skips_missing_guid_and_other_eids():
    batch = [
        _ev(event_id=1, process_guid="{C}", parent_process_guid=""),  # no parent
        _ev(event_id=1, process_guid="", parent_process_guid="{P}"),  # no child
        _ev(event_id=3, process_guid="{C}", parent_process_guid="{P}"),  # wrong eid
    ]
    assert sysmon_spawn_rows(batch) == []


def test_spawn_loader_emits_sysmon_relationship_only_for_valid_rows():
    loader, client = _loader()
    batch = [
        _ev(event_id=1, process_guid="{C}", parent_process_guid="{P}", image="x.exe"),
        _ev(event_id=4688, image="cmd.exe"),  # 4688 must NOT become a sysmon spawn
    ]
    loader._ingest_sysmon_spawn(batch)
    assert len(client.calls) == 1
    query, rows = client.calls[0]
    assert "SPAWNED {source: 'sysmon'}" in query
    assert len(rows) == 1


# --- CONNECTED_TO (Sysmon EID 3) -------------------------------------------


def test_connection_rows_shapes_and_skips_loopback():
    batch = [
        _ev(
            event_id=3,
            image=r"C:\app.exe",
            process_guid="{G}",
            process_id="900",
            ip="93.184.216.34",
            port="443",
            protocol="tcp",
        ),
        _ev(event_id=3, process_guid="{G}", ip="127.0.0.1"),  # loopback -> skip
        _ev(event_id=3, process_guid="", ip="8.8.8.8"),  # no guid -> skip
        _ev(event_id=1, process_guid="{G}", ip="8.8.8.8"),  # wrong eid
    ]
    rows = sysmon_connection_rows(batch)
    assert len(rows) == 1
    r = rows[0]
    assert r["proc_id"] == "HOST:guid:{G}"
    assert r["proc_name"] == "app.exe"
    assert r["pid"] == 900
    assert r["address"] == "93.184.216.34"
    assert r["port"] == 443
    assert r["protocol"] == "tcp"


def test_connection_loader_emits_connected_to():
    loader, client = _loader()
    loader._ingest_connections([_ev(event_id=3, process_guid="{G}", ip="1.2.3.4")])
    query, rows = client.calls[0]
    assert "CONNECTED_TO" in query and "IPAddress" in query
    assert len(rows) == 1


# --- LOGGED_IN (4624) -------------------------------------------------------


def test_logon_rows_carry_logontype_and_ip():
    batch = [
        _ev(event_id=4624, target_user="rsydow", logon_type="10", ip="172.16.5.26"),
        _ev(event_id=4624, target_user=""),  # no user -> skip
        _ev(event_id=4625, target_user="rsydow"),  # failed logon -> skip
    ]
    rows = logon_rows(batch)
    assert len(rows) == 1
    assert rows[0]["logon_type"] == "10"
    assert rows[0]["ip"] == "172.16.5.26"
    assert rows[0]["user"] == "rsydow"


def test_logon_loader_sets_logontype_property():
    loader, client = _loader()
    loader._ingest_logons([_ev(event_id=4624, target_user="u", logon_type="3")])
    query, rows = client.calls[0]
    assert "LOGGED_IN" in query
    assert "l.logonType = r.logon_type" in query
    assert "l.ip = r.ip" in query
    assert len(rows) == 1


# --- MODIFIED (Sysmon EID 12/13) -------------------------------------------


def test_registry_rows_for_12_and_13_only():
    batch = [
        _ev(event_id=12, process_guid="{G}", registry_key=r"HKLM\...\Run", image="p.exe"),
        _ev(event_id=13, process_guid="{G}", registry_key=r"HKLM\...\Services"),
        _ev(event_id=14, process_guid="{G}", registry_key=r"HKLM\x"),  # rename -> skip
        _ev(event_id=12, process_guid="", registry_key=r"HKLM\y"),  # no guid -> skip
    ]
    rows = sysmon_registry_rows(batch)
    assert len(rows) == 2
    assert rows[0]["registry_id"] == r"HOST:HKLM\...\Run"
    assert rows[0]["proc_name"] == "p.exe"


def test_registry_loader_emits_modified_to_registrykey():
    loader, client = _loader()
    loader._ingest_modified_registry(
        [_ev(event_id=13, process_guid="{G}", registry_key=r"HKLM\Run")]
    )
    query, rows = client.calls[0]
    assert "[m:MODIFIED]" in query and "RegistryKey" in query
    assert len(rows) == 1


# --- CREATED_FILE / DELETED_FILE (Sysmon EID 11/23) ------------------------


def test_file_rows_create_vs_delete_flag():
    batch = [
        _ev(event_id=11, id="h:create", target_filename=r"C:\a\n.ps1"),
        _ev(event_id=23, id="h:delete", target_filename=r"C:\a\old.tmp"),
        _ev(event_id=11, target_filename=""),  # empty path -> skip
        _ev(event_id=1, target_filename=r"C:\a\x"),  # wrong eid -> skip
    ]
    rows = sysmon_file_rows(batch)
    assert len(rows) == 2
    by_id = {r["event_node_id"]: r for r in rows}
    assert by_id["h:create"]["deleted"] is False
    assert by_id["h:create"]["name"] == "n.ps1"
    assert by_id["h:create"]["file_id"] == r"HOST:C:\a\n.ps1"
    assert by_id["h:delete"]["deleted"] is True


def test_file_touch_loader_splits_created_and_deleted():
    loader, client = _loader()
    batch = [
        _ev(event_id=11, id="h:c", target_filename=r"C:\a\n.ps1"),
        _ev(event_id=23, id="h:d", target_filename=r"C:\a\old.tmp"),
    ]
    loader._ingest_file_touch(batch)
    assert len(client.calls) == 2
    queries = [q for q, _ in client.calls]
    assert any("[:CREATED_FILE]" in q for q in queries)
    assert any("[:DELETED_FILE]" in q for q in queries)
    # each call carries exactly its one matching row
    for q, rows in client.calls:
        assert len(rows) == 1


def test_file_touch_loader_noop_when_empty():
    loader, client = _loader()
    loader._ingest_file_touch([_ev(event_id=1)])
    assert client.calls == []
