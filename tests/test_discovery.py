from forensics.case import CaseManifest
from forensics.discovery import discovery_from_case, match_score


def _case(**kwargs):
    return CaseManifest(
        case_id="t",
        title="t",
        case_type="insider_ip_theft",
        brief=__import__("pathlib").Path("brief.md"),
        playbook="insider_ip_theft",
        sensitive_paths=[r"\Users\*\Documents\*"],
        filename_keywords=["HEA", "srl"],
        discovery={
            "token_keywords": ["srl", "alloy"],
            "path_aliases": {"HEA": ["high-entropy"]},
            "min_keyword_len": 4,
        },
        **kwargs,
    )


def test_hea_word_boundary_not_security_health():
    case = _case()
    assert match_score(r"C:\Windows\System32\SecurityHealthService.exe", case) < 0.4


def test_srl_path_scores_high():
    case = _case()
    assert match_score(r"C:\Users\fred\Documents\SRL\alloy_v2.dwg", case) >= 0.4


def test_high_entropy_alias():
    case = _case()
    assert match_score(r"D:\Design\high-entropy\sim.hec", case) >= 0.4


def test_discovery_from_case():
    case = _case()
    disc = discovery_from_case(case)
    assert "srl" in disc.token_keywords
