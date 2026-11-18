from __future__ import annotations

from datetime import UTC, datetime

from p2c.scanning.catalog import CATALOG, CheckId, build_finding, is_valid_control_id
from p2c.scanning.cvss import base_score
from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import severity_from_cvss

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_every_check_is_in_the_catalog() -> None:
    assert set(CATALOG) == set(CheckId)


HARDENING_ONLY = {
    CheckId.MISSING_HSTS,
    CheckId.MISSING_CSP,
    CheckId.MISSING_X_FRAME_OPTIONS,
    CheckId.MISSING_X_CONTENT_TYPE_OPTIONS,
    CheckId.MISSING_REFERRER_POLICY,
    CheckId.MISSING_PERMISSIONS_POLICY,
    CheckId.INSECURE_COOKIE,
    CheckId.DIRECTORY_LISTING_ENABLED,
    CheckId.EXPOSED_SENSITIVE_FILE,
    CheckId.DKIM_MISSING,
    CheckId.MTA_STS_MISSING,
    CheckId.WAF_ABSENT,
    CheckId.NO_DDOS_PROTECTION,
    CheckId.EXPOSED_LOGIN_PANEL,
    CheckId.EXPOSED_DEV_ENVIRONMENT,
}


def test_catalog_covers_the_eleven_tier1_subcontrols() -> None:
    assert len(CATALOG) == 32
    linked = {check for check, spec in CATALOG.items() if spec.control_ids}
    assert set(CATALOG) - linked == HARDENING_ONLY
    controls = {cid for spec in CATALOG.values() for cid in spec.control_ids}
    assert controls == {
        "2-3-3-3",
        "2-4-3-5",
        "2-5-3-1",
        "2-5-3-5",
        "2-5-3-7",
        "2-7-1-3",
        "2-8-3-1",
        "2-8-3-2",
        "2-8-3-3",
        "2-10-3-4",
        "2-15-3-3",
    }


def test_catalog_severity_matches_cvss_band() -> None:
    for spec in CATALOG.values():
        assert spec.severity == severity_from_cvss(spec.cvss_score).value
        assert spec.evidence_tier is EvidenceTier.TIER_1
        assert spec.control_ids or spec.check_id in HARDENING_ONLY


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
        CheckId.NO_HTTPS_REDIRECT,
        asset="www.example.com",
        observed_state="HTTP served without a redirect to HTTPS",
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
        CheckId.NO_HTTPS_REDIRECT,
        asset="a",
        observed_state="x",
        consent_ref="C1",
        source_tool="nuclei",
        tool_version="v3.10.0",
        extra_control_ids=("2-15-3-3", "2-8-3-3"),
    )
    assert finding.control_ids == ["2-15-3-3", "2-8-3-3"]
