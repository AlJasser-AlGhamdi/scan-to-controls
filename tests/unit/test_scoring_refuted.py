from __future__ import annotations

from datetime import UTC, datetime

import pytest

from p2c.mapping.rules import MappingEngine
from p2c.scanning.catalog import CheckId, build_finding
from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import Attestation
from p2c.scoring.assemble import merge_assessments
from p2c.scoring.contradictions import detect_contradictions
from p2c.scoring.dual_score import compute_dual_score
from p2c.scoring.models import ComplianceStatus, ControlAssessment
from p2c.scoring.questionnaire import Question, Questionnaire

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _mk(cid: str, tier: EvidenceTier, status: ComplianceStatus) -> ControlAssessment:
    return ControlAssessment(control_id=cid, tier=tier, status=status, weight=1.0)


def test_parent_attestation_refuted_by_child_finding_cannot_inflate_documented() -> None:
    merged = merge_assessments(
        [_mk("2-4-3-5", EvidenceTier.TIER_1, ComplianceStatus.NON_COMPLIANT)],
        [_mk("2-4-3", EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT)],
    )
    parent = next(a for a in merged if a.control_id == "2-4-3")
    assert parent.status == ComplianceStatus.NON_COMPLIANT
    assert compute_dual_score(merged).documented_score == 0.0


def test_child_attestation_refuted_by_parent_finding_is_neutralized() -> None:
    merged = merge_assessments(
        [_mk("2-4-3", EvidenceTier.TIER_1, ComplianceStatus.NON_COMPLIANT)],
        [_mk("2-4-3-5", EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT)],
    )
    child = next(a for a in merged if a.control_id == "2-4-3-5")
    assert child.status == ComplianceStatus.NON_COMPLIANT
    assert compute_dual_score(merged).documented_score == 0.0


def test_unrelated_attestation_still_lifts_documented() -> None:
    merged = merge_assessments(
        [_mk("2-4-3-5", EvidenceTier.TIER_1, ComplianceStatus.NON_COMPLIANT)],
        [_mk("1-3-2", EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT)],
    )
    assert next(a for a in merged if a.control_id == "1-3-2").status == ComplianceStatus.COMPLIANT
    score = compute_dual_score(merged)
    assert score.documented_score == 0.5
    assert score.assessed_score == 0.0


def test_questionnaire_rejects_tier1() -> None:
    with pytest.raises(ValueError, match="TIER_2 or TIER_3"):
        Questionnaire(
            questionnaire_id="q",
            title="t",
            tier=EvidenceTier.TIER_1,
            questions=[Question(question_id="a", control_id="1-3-2", prompt_en="x")],
        )


def test_detect_contradictions_respects_validity_window_when_now_given() -> None:
    findings = MappingEngine().map_findings(
        [
            build_finding(
                CheckId.SPF_MISSING,
                asset="x.sa",
                observed_state="o",
                consent_ref="C",
                source_tool="s",
                tool_version="0",
                now=NOW,
            )
        ]
    )
    expired = Attestation(
        attestation_id="A",
        control_id="2-4-3-5",
        statement="done",
        signer_identity="ciso",
        payload_hash="h",
        valid_from=datetime(2024, 1, 1, tzinfo=UTC),
        valid_until=datetime(2024, 6, 1, tzinfo=UTC),
    )
    assert len(detect_contradictions([expired], findings)) == 1
    assert detect_contradictions([expired], findings, now=NOW) == []
