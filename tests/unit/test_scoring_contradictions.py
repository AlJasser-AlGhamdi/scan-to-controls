from __future__ import annotations

from datetime import UTC, datetime

from p2c.mapping.rules import MappingEngine
from p2c.scanning.catalog import CheckId, build_finding
from p2c.schemas.models import Attestation
from p2c.scoring.assemble import (
    attestation_assessments,
    merge_assessments,
    tier1_assessments,
)
from p2c.scoring.contradictions import detect_contradictions
from p2c.scoring.models import ComplianceStatus

NOW = datetime(2026, 1, 1, tzinfo=UTC)
LATER = datetime(2027, 1, 1, tzinfo=UTC)


def _mappings(*checks: CheckId):
    findings = [
        build_finding(
            c,
            asset="x.example",
            observed_state="o",
            consent_ref="C1",
            source_tool="s",
            tool_version="0",
            now=NOW,
        )
        for c in checks
    ]
    return MappingEngine().map_findings(findings)


def _attest(control_id: str) -> Attestation:
    return Attestation(
        attestation_id=f"A-{control_id}",
        control_id=control_id,
        statement="control fully implemented",
        signer_identity="ciso",
        payload_hash="h",
        valid_from=NOW,
        valid_until=LATER,
    )


def test_attestation_refuted_by_tier1_finding_is_flagged() -> None:
    mappings = _mappings(CheckId.SPF_MISSING)
    contradictions = detect_contradictions([_attest("2-4-3-5")], mappings)
    assert len(contradictions) == 1
    assert contradictions[0].control_id == "2-4-3-5"
    assert contradictions[0].finding_id == "spf_missing:x.example"


def test_no_contradiction_without_a_refuting_finding() -> None:
    mappings = _mappings(CheckId.SPF_MISSING)
    assert detect_contradictions([_attest("2-6-3-1")], mappings) == []


def test_contradiction_output_is_sorted_and_deterministic() -> None:
    mappings = _mappings(CheckId.SPF_MISSING, CheckId.MISSING_HSTS)
    contradictions = detect_contradictions([_attest("2-8-3-3"), _attest("2-4-3-5")], mappings)
    assert [c.control_id for c in contradictions] == ["2-4-3-5", "2-8-3-3"]


def test_tier1_evidence_overrides_attestation_in_merge() -> None:
    mappings = _mappings(CheckId.SPF_MISSING)
    merged = {
        a.control_id: a
        for a in merge_assessments(
            tier1_assessments(mappings), attestation_assessments([_attest("2-4-3-5")], now=NOW)
        )
    }
    assert merged["2-4-3-5"].tier.value == 1
    assert merged["2-4-3-5"].status is ComplianceStatus.NON_COMPLIANT


def test_attestation_assessments_drops_expired_attestation() -> None:
    expired = _attest("2-4-3-5").model_copy(
        update={
            "valid_from": datetime(2024, 1, 1, tzinfo=UTC),
            "valid_until": datetime(2025, 1, 1, tzinfo=UTC),
        }
    )
    assert attestation_assessments([expired], now=NOW) == []
    assert len(attestation_assessments([_attest("2-4-3-5")], now=NOW)) == 1


def test_tier1_assessments_mark_unfound_controls_compliant() -> None:
    mappings = _mappings(CheckId.SPF_MISSING)
    assessments = {a.control_id: a for a in tier1_assessments(mappings)}
    assert assessments["2-4-3-5"].status is ComplianceStatus.NON_COMPLIANT
    assert assessments["2-8-3-3"].status is ComplianceStatus.COMPLIANT
    assert all(a.tier.value == 1 for a in assessments.values())


def test_tier1_finding_outside_checkable_is_not_dropped() -> None:
    finding = build_finding(
        CheckId.SPF_MISSING,
        asset="x.example",
        observed_state="o",
        consent_ref="C1",
        source_tool="nuclei",
        tool_version="0",
        extra_control_ids=("2-3-3-3",),
        now=NOW,
    )
    mappings = MappingEngine().map_findings([finding])
    assessments = {a.control_id: a for a in tier1_assessments(mappings)}
    assert "2-3-3-3" in assessments
    assert assessments["2-3-3-3"].status is ComplianceStatus.NON_COMPLIANT


def test_coarse_parent_attestation_is_flagged_against_child_finding() -> None:
    mappings = _mappings(CheckId.SPF_MISSING)
    contradictions = detect_contradictions([_attest("2-4-3")], mappings)
    assert len(contradictions) == 1
    assert contradictions[0].control_id == "2-4-3"
    assert contradictions[0].finding_id == "spf_missing:x.example"
