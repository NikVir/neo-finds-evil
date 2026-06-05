from forensics.paths import extract_file_path, file_node_id


def test_extract_display_name():
    raw = {"display_name": r"C:\Users\a\file.txt", "filename": "file.txt"}
    assert extract_file_path(raw) == r"C:\Users\a\file.txt"


def test_file_node_id():
    assert file_node_id("Rocba", r"C:\x.txt") == r"Rocba:C:\x.txt"
