from forensics.timestamps import normalize_timestamp


def test_iso_passthrough():
    assert normalize_timestamp("2020-10-15T12:00:00Z") == "2020-10-15T12:00:00Z"


def test_empty():
    assert normalize_timestamp("") == ""
    assert normalize_timestamp(None) == ""
