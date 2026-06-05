from forensics.event_profile import (
    allowed_eids,
    build_psort_evtx_filter,
    load_profile,
    profile_for_case_type,
)


def test_intrusion_profile_has_sysmon_1():
    p = load_profile("intrusion")
    assert 1 in allowed_eids(p)
    assert 22 in allowed_eids(p)
    assert 4624 in allowed_eids(p)


def test_insider_subset_excludes_account_wmi():
    p = profile_for_case_type("insider_ip_theft")
    eids = allowed_eids(p)
    assert 1 in eids
    assert 4720 not in eids
    assert 5861 not in eids


def test_psort_filter_contains_data_type():
    p = load_profile("intrusion")
    filt = build_psort_evtx_filter(p)
    assert 'data_type is "windows:evtx:record"' in filt
    assert "event_identifier is 1" in filt


def test_account_compromise_profile_auth_only():
    from forensics.event_profile import allowed_eids_for_packs

    p = profile_for_case_type("account_compromise")
    eids = allowed_eids(p)
    assert 4624 in eids
    assert 4625 in eids
    assert 1 not in eids

    intrusion = load_profile("intrusion")
    triage = allowed_eids_for_packs(intrusion, frozenset({"security_auth"}))
    assert 4624 in triage
    assert 1 not in triage
