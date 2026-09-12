from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from p2c.schemas import (
    Asset,
    Attestation,
    Consent,
    EvidenceTier,
    Finding,
    ScanIntensity,
    Score,
    Severity,
)


def _finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "finding_id": "F1",
        "asset": "asset-1",
        "source_tool": "nuclei",
        "tool_version": "v3.10.0",
        "observed_state": "HSTS header missing",
        "severity": Severity.MEDIUM,
        "evidence_tier": EvidenceTier.TIER_1,
        "consent_ref": "C1",
        "cvss_base_score": 5.3,
    }
    base.update(overrides)
    return Finding(**base)


def test_finding_json_roundtrip() -> None:
    finding = _finding()
    restored = Finding.model_validate_json(finding.model_dump_json())
    assert restored == finding


def test_finding_severity_must_match_cvss_band() -> None:
    with pytest.raises(ValidationError):
        _finding(cvss_base_score=9.5, severity=Severity.LOW)


def test_finding_cvss_out_of_range_rejected() -> None:
    with pytest.raises(ValidationError):
        _finding(cvss_base_score=11.0, severity=Severity.CRITICAL)


def test_finding_without_cvss_allows_any_severity() -> None:
    finding = _finding(cvss_base_score=None, cvss_v3_1_vector=None, severity=Severity.HIGH)
    assert finding.severity is Severity.HIGH
    assert finding.control_ids == []


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        Asset(
            asset_id="a",
            value="ex.com",
            asset_type="domain",
            source_tool="subfinder",
            tool_version="v2.14.0",
            discovery_method="synthetic",
            consent_ref="C1",
            bogus_field=1,
        )


def test_score_gap_is_derived() -> None:
    score = Score(subject_id="p1", assessed_score=0.4, documented_score=0.85)
    assert score.gap == pytest.approx(0.6)


@pytest.mark.parametrize(("assessed", "gap"), [(0.0, 1.0), (1.0, 0.0), (0.25, 0.75)])
def test_score_gap_matches_one_minus_assessed(assessed: float, gap: float) -> None:
    score = Score(subject_id="p", assessed_score=assessed, documented_score=assessed)
    assert score.gap == pytest.approx(gap)


def test_consent_window_must_be_ordered() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        Consent(
            consent_id="C1",
            verified_apex="ex.com",
            time_window_start=now,
            time_window_end=now - timedelta(hours=1),
            verification_method="dns-txt",
        )


def test_consent_is_active_window() -> None:
    now = datetime.now(UTC)
    consent = Consent(
        consent_id="C1",
        verified_apex="ex.com",
        time_window_start=now - timedelta(hours=1),
        time_window_end=now + timedelta(hours=1),
        allowed_intensity=ScanIntensity.SAFE_ACTIVE,
        verification_method="dns-txt",
    )
    assert consent.is_active(now)
    assert not consent.is_active(now + timedelta(hours=2))


def test_consent_naive_datetimes_normalized_and_is_active_safe() -> None:
    naive = datetime(2020, 1, 1, 0, 0, 0)
    consent = Consent.model_validate(
        {
            "consent_id": "C1",
            "verified_apex": "ex.com",
            "time_window_start": naive,
            "time_window_end": datetime(2999, 1, 1, 0, 0, 0),
            "verification_method": "dns-txt",
        }
    )
    assert consent.time_window_start.tzinfo is not None
    assert consent.is_active() is True
    assert consent.is_active(datetime(2010, 1, 1)) is False


def test_attestation_validity_ordered() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        Attestation(
            attestation_id="AT1",
            control_id="2-5-3-1",
            statement="firewall in place",
            signer_identity="cn=atlas",
            payload_hash="deadbeef",
            valid_from=now,
            valid_until=now - timedelta(days=1),
        )
