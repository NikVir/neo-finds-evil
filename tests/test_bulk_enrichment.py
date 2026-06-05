"""Tests for bulk_extractor case gating."""

from forensics.case import CaseManifest, Hypothesis
from forensics.ingest.loaders.bulk_extractor import bulk_enabled_for_case


def test_bulk_disabled_by_default() -> None:
    case = CaseManifest(
        case_id="x",
        title="t",
        case_type="intrusion",
        brief=__file__,
        playbook="intrusion",
        enrichment={"bulk_extractor": "false"},
    )
    assert bulk_enabled_for_case(case) is False


def test_bulk_auto_open_hypothesis() -> None:
    case = CaseManifest(
        case_id="x",
        title="t",
        case_type="intrusion",
        brief=__file__,
        playbook="intrusion",
        enrichment={"bulk_extractor": "auto", "bulk_hypotheses": ["EXFIL-CLOUD"]},
        hypotheses=[
            Hypothesis(id="EXFIL-CLOUD", statement="s", status="open"),
        ],
    )
    assert bulk_enabled_for_case(case) is True
