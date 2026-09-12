from __future__ import annotations

from datetime import UTC, datetime

from p2c.scanning.catalog import CATALOG, CheckId, build_finding, is_valid_control_id
from p2c.scanning.cvss import base_score
from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import severity_from_cvss

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_every_check_is_in_the_catalog() -> None:
    assert set(CATALOG) == set(CheckId)


def test_catalog_covers_sixteen_tier1_controls() -> None:
    controls = {cid for spec in CATALOG.values() for cid in spec.control_ids}
    assert len(CATALOG) == 31
    assert controls == {
        "2-2-3-1",
        "2-2-3-2",
        "2-3-3-3",
        "2-4-3-5",
        "2-5-3-1",
        "2-5-3-2",
        "2-5-3-5",
        "2-5-3-7",
        "2-5-3-9",
        "2-10-3-1",
        "2-10-3-4",
        "2-15-3-1",
        "2-15-3-2",
        "2-15-3-3",
        "2-15-3-5",
        "2-8-3-3",
    }


def test_catalog_severity_matches_cvss_band() -> None:
    for spec in CATALOG.values():
        assert spec.severity == severity_from_cvss(spec.cvss_score).value
        assert spec.evidence_tier is EvidenceTier.TIER_1
        assert spec.control_ids


def test_catalog_cvss_vector_computes_to_recorded_score() -> None:
    for spec in CATALOG.values():
        assert base_score(spec.cvss_vector) == spec.cvss_score, spec.check_id


def test_catalog_control_ids_are_well_formed() -> None:
    for spec in CATALOG.values():
        assert all(is_valid_control_id(cid) for cid in spec.control_ids), spec.check_id


def test_is_valid_control_id() -> None:
    assert is_valid_control_id("2-15-3-3")
    assert is_valid_control_id("2-7")
    assert not is_valid_control_id("drop table controls")
    assert not is_valid_control_id("2--3")
    assert not is_valid_control_id("")


def test_build_finding_is_control_tagged_and_consistent() -> None:
    finding = build_finding(
        CheckId.MISSING_HSTS,
        asset="www.example.com",
        observed_state="HSTS absent",
        consent_ref="C1",
        source_tool="atlas-scan:http-headers",
        tool_version="0.0.0",
        now=NOW,
    )
    assert finding.control_ids == ["2-15-3-3", "2-8-3-3"]
    assert finding.evidence_tier is EvidenceTier.TIER_1
    assert finding.severity is severity_from_cvss(finding.cvss_base_score)
    assert finding.cvss_v3_1_vector and finding.cvss_v3_1_vector.startswith("CVSS:3.1/")
    assert finding.timestamp == NOW


def test_build_finding_merges_extra_control_ids_without_dupes() -> None:
    finding = build_finding(
        CheckId.MISSING_HSTS,
        asset="a",
        observed_state="x",
        consent_ref="C1",
        source_tool="nuclei",
        tool_version="v3.10.0",
        extra_control_ids=("2-15-3-3", "2-8-3-3"),
    )
    assert finding.control_ids == ["2-15-3-3", "2-8-3-3"]
