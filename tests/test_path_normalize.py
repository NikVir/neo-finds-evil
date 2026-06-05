"""Tests for path normalization."""

from forensics.path_normalize import normalize_windows_path, normalized_file_id


def test_device_harddisk_volume_to_c() -> None:
    p = r"\Device\HarddiskVolume1\Windows\System32\cmd.exe"
    assert normalize_windows_path(p) == r"C:\Windows\System32\cmd.exe"


def test_forward_slashes() -> None:
    assert normalize_windows_path("C:/Users/foo/bar.exe") == r"C:\Users\foo\bar.exe"


def test_file_node_id() -> None:
    norm, fid = normalized_file_id("Host1", r"\Device\HarddiskVolume1\foo.exe")
    assert norm == r"C:\foo.exe"
    assert fid == r"Host1:C:\foo.exe"
