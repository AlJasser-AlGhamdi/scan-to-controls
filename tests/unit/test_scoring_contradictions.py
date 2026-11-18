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
    mappings = _mappings(CheckId.SPF_MISSING, CheckId.NO_HTTPS_REDIRECT)
    contradictions = detect_contradictions([_attest("2-8-3-3"), _attest("2-4-3-5")], mappings)
    assert [c.control_id for c in contradictions] == ["2-4-3-5", "2-8-3-3"]


def test_tier1_evidence_overrides_attestation_in_merge() -> None:
    mappings = _mappings(CheckId.SPF_MISSING)
    merged = {
        a.control_id: a
        for a in merge_assessments(
            tier1_assessments(mappings, unobserved=frozenset()),
            attestation_assessments([_attest("2-4-3-5")], now=NOW),
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
    assessments = {a.control_id: a for a in tier1_assessments(mappings, unobserved=frozenset())}
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
    assessments = {a.control_id: a for a in tier1_assessments(mappings, unobserved=frozenset())}
    assert "2-3-3-3" in assessments
    assert assessments["2-3-3-3"].status is ComplianceStatus.NON_COMPLIANT


def test_coarse_parent_attestation_is_flagged_against_child_finding() -> None:
    mappings = _mappings(CheckId.SPF_MISSING)
    contradictions = detect_contradictions([_attest("2-4-3")], mappings)
    assert len(contradictions) == 1
    assert contradictions[0].control_id == "2-4-3"
    assert contradictions[0].finding_id == "spf_missing:x.example"




def _at(control_id: str, mappings):
    return [m.model_copy(update={"control_id": control_id}) for m in mappings]


def test_parent_level_finding_never_flags_a_child_declaration() -> None:
    parent_finding = _at("2-15-3", _mappings(CheckId.NO_HTTPS_REDIRECT))
    for child in ("2-15-3-1", "2-15-3-3", "2-15-3-5"):
        assert detect_contradictions([_attest(child)], parent_finding) == [], child


def test_parent_declaration_with_child_finding_is_flagged() -> None:
    mappings = _mappings(CheckId.NO_HTTPS_REDIRECT)
    flagged = detect_contradictions([_attest("2-15-3")], mappings)
    assert [c.control_id for c in flagged] == ["2-15-3"]


def test_child_finding_never_flags_a_sibling_declaration() -> None:
    mappings = _mappings(CheckId.NO_HTTPS_REDIRECT)
    assert detect_contradictions([_attest("2-15-3-1"), _attest("2-15-3-5")], mappings) == []




def _tier2(control_id: str, status: ComplianceStatus, evidence: list[str] | None = None):
    from p2c.schemas.enums import EvidenceTier
    from p2c.scoring.models import ControlAssessment

    return ControlAssessment(
        control_id=control_id,
        tier=EvidenceTier.TIER_2,
        status=status,
        evidence_ids=evidence or [],
        source="questionnaire",
    )


def test_tier2_compliance_claim_refuted_by_finding_is_flagged() -> None:
    mappings = _mappings(CheckId.SPF_MISSING)
    claim = _tier2("2-4-3-5", ComplianceStatus.COMPLIANT, ["Q-7"])
    flagged = detect_contradictions([], mappings, tier2=[claim])
    assert len(flagged) == 1
    assert flagged[0].control_id == "2-4-3-5"
    assert flagged[0].attestation_id == "Q-7"
    assert flagged[0].tier == 2


def test_tier2_record_without_evidence_id_gets_a_stable_id() -> None:
    mappings = _mappings(CheckId.SPF_MISSING)
    flagged = detect_contradictions([], mappings, tier2=[_tier2("2-4-3-5", ComplianceStatus.COMPLIANT)])
    assert flagged[0].attestation_id == "tier2:2-4-3-5"


def test_tier2_gap_record_is_not_a_contradiction() -> None:
    mappings = _mappings(CheckId.SPF_MISSING)
    gap = _tier2("2-4-3-5", ComplianceStatus.NON_COMPLIANT)
    assert detect_contradictions([], mappings, tier2=[gap]) == []


def test_tier3_contradictions_default_to_tier_3() -> None:
    flagged = detect_contradictions([_attest("2-4-3-5")], _mappings(CheckId.SPF_MISSING))
    assert flagged[0].tier == 3


def test_a_claim_that_a_list_is_implemented_is_contradicted_by_a_finding_on_the_list() -> None:
    import json
    from pathlib import Path

    from p2c.scoring.contradictions import IMPLEMENTS, control_related, hierarchy_related

    assert control_related("2-5-2", "2-5-3-1") and control_related("2-15-2", "2-15-3")
    assert not control_related("2-5-2", "2-4-3-5") and not control_related("2-5-3-1", "2-5-2")
    assert not hierarchy_related("2-5-2", "2-5-3-1")
    root = Path(__file__).resolve().parents[2]
    overlay = json.loads((root / "taxonomy/release/sort_overlay.json").read_text(encoding="utf-8"))
    rows = {r["id"]: r for r in overlay["controls"]}
    for implements, listed in IMPLEMENTS.items():
        assert rows[implements]["kind"] == "main" and int(rows[implements]["tier"]) == 2
        assert not any(c.startswith(f"{implements}-") for c in rows)
        assert any(c.startswith(f"{listed}-") and int(r["tier"]) == 1 for c, r in rows.items())
