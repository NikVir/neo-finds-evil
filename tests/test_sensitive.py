from forensics.sensitive import path_matches_sensitive


def test_documents_glob():
    assert path_matches_sensitive(
        r"C:\Users\alice\Documents\secret.docx",
        [r"\Users\*\Documents\*"],
    )


def test_extension():
    assert path_matches_sensitive(
        r"C:\Design\part1.dwg",
        [],
        extensions=[".dwg"],
    )


def test_no_match():
    assert not path_matches_sensitive(
        r"C:\Windows\System32\cmd.exe",
        [r"\Users\*\Documents\*"],
    )
