from __future__ import annotations

import pytest

from p2c.scoring.models import ComplianceStatus
from p2c.scoring.questionnaire import (
    Answer,
    EvidenceKind,
    Question,
    Questionnaire,
    QuestionnaireEngine,
    QuestionnaireError,
    QuestionnaireResponse,
)
from p2c.sovereignty.provenance import content_hash


def _questionnaire() -> Questionnaire:
    return Questionnaire(
        questionnaire_id="Q1",
        title="IAM",
        questions=[
            Question(
                question_id="q1",
                control_id="2-2-3-3",
                prompt_en="Least privilege?",
                evidence_kind=EvidenceKind.UPLOAD,
            ),
            Question(question_id="q2", control_id="2-2-4", prompt_en="IAM reviewed?"),
            Question(question_id="q3", control_id="2-2-1", prompt_en="IAM policy?", required=False),
        ],
    )


def _response(answers: list[Answer]) -> QuestionnaireResponse:
    return QuestionnaireResponse(questionnaire_id="Q1", respondent="admin", consent_ref="C1", answers=answers)


def test_duplicate_question_id_rejected_at_definition() -> None:
    with pytest.raises(ValueError, match="duplicate question_id"):
        Questionnaire(
            questionnaire_id="Q",
            title="t",
            questions=[
                Question(question_id="q1", control_id="2-2-1", prompt_en="a"),
                Question(question_id="q1", control_id="2-2-2", prompt_en="b"),
            ],
        )


def test_response_validation_errors() -> None:
    engine = QuestionnaireEngine()
    q = _questionnaire()
    with pytest.raises(QuestionnaireError, match="does not match"):
        engine.validate(q, QuestionnaireResponse(questionnaire_id="OTHER", respondent="a", consent_ref="C1"))
    with pytest.raises(QuestionnaireError, match="unknown question"):
        engine.validate(q, _response([Answer(question_id="zzz", compliant=True)]))
    with pytest.raises(QuestionnaireError, match="required"):
        engine.validate(q, _response([Answer(question_id="q1", compliant=True)]))
    with pytest.raises(QuestionnaireError, match="duplicate"):
        engine.validate(
            q,
            _response(
                [
                    Answer(question_id="q1", compliant=True),
                    Answer(question_id="q1", compliant=False),
                    Answer(question_id="q2", compliant=True),
                ]
            ),
        )


def test_valid_response_passes() -> None:
    q = _questionnaire()
    resp = _response(
        [Answer(question_id="q1", compliant=True, content="doc"), Answer(question_id="q2", compliant=True)]
    )
    QuestionnaireEngine().validate(q, resp)


def test_upload_evidence_is_content_hashed_with_provenance() -> None:
    q = _questionnaire()
    resp = _response(
        [
            Answer(question_id="q1", compliant=True, content="access-review.pdf"),
            Answer(question_id="q2", compliant=True),
        ]
    )
    evidence = QuestionnaireEngine().evidence(q, resp)
    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.control_id == "2-2-3-3"
    assert ev.content_hash == content_hash("access-review.pdf")
    assert ev.evidence_tier.value == 2
    assert ev.source == "questionnaire:admin"
    assert ev.consent_ref == "C1"


def test_two_uploads_same_control_link_to_distinct_evidence() -> None:
    q = Questionnaire(
        questionnaire_id="Q",
        title="dup",
        questions=[
            Question(
                question_id="qa", control_id="2-2-3-3", prompt_en="a", evidence_kind=EvidenceKind.UPLOAD
            ),
            Question(
                question_id="qb", control_id="2-2-3-3", prompt_en="b", evidence_kind=EvidenceKind.UPLOAD
            ),
        ],
    )
    resp = QuestionnaireResponse(
        questionnaire_id="Q",
        respondent="admin",
        consent_ref="C1",
        answers=[
            Answer(question_id="qa", compliant=True, content="DOC-A"),
            Answer(question_id="qb", compliant=True, content="DOC-B"),
        ],
    )
    engine = QuestionnaireEngine()
    evidence = {ev.evidence_id: ev for ev in engine.evidence(q, resp)}
    assert set(evidence) == {"ev:Q:qa", "ev:Q:qb"}
    assert evidence["ev:Q:qa"].content_hash == content_hash("DOC-A")
    assert evidence["ev:Q:qb"].content_hash == content_hash("DOC-B")
    assessments = engine.assessments(q, resp)
    linked = sorted(ev for a in assessments for ev in a.evidence_ids)
    assert linked == ["ev:Q:qa", "ev:Q:qb"]


def test_empty_consent_ref_is_rejected() -> None:
    with pytest.raises(ValueError, match="consent_ref"):
        QuestionnaireResponse(questionnaire_id="Q", respondent="a", consent_ref="")


def test_assessments_reflect_answers() -> None:
    q = _questionnaire()
    resp = _response(
        [Answer(question_id="q1", compliant=True, content="doc"), Answer(question_id="q2", compliant=False)]
    )
    assessments = {a.control_id: a for a in QuestionnaireEngine().assessments(q, resp)}
    assert assessments["2-2-3-3"].status is ComplianceStatus.COMPLIANT
    assert assessments["2-2-3-3"].evidence_ids
    assert assessments["2-2-4"].status is ComplianceStatus.NON_COMPLIANT
    assert assessments["2-2-1"].status is ComplianceStatus.NOT_ASSESSED
    assert all(a.tier.value == 2 for a in assessments.values())
