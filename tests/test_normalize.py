from forensics.normalize import normalize_record, process_id


def test_normalize_volatility_keys() -> None:
    raw = {"PID": 4, "ImageFileName": "System", "Offset(V)": 123, "File output": "Disabled"}
    out = normalize_record(raw)
    assert out["pid"] == 4
    assert out["image_file_name"] == "System"
    assert out["offset_v"] == 123


def test_process_id() -> None:
    pid = process_id("Rocba", 100, "2020-11-11T08:13:00+00:00")
    assert pid.startswith("Rocba:100:")
