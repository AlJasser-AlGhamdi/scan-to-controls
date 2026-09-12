from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import Field, model_validator

from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import AtlasModel, Evidence
from p2c.scoring.models import ComplianceStatus, ControlAssessment
from p2c.sovereignty.provenance import content_hash


def _utcnow() -> datetime:
    return datetime.now(UTC)


class EvidenceKind(StrEnum):

    BOOLEAN = "boolean"
    UPLOAD = "upload"
    ATTESTATION = "attestation"


class Question(AtlasModel):

    question_id: str
    control_id: str
    prompt_en: str
    prompt_ar: str = ""
    evidence_kind: EvidenceKind = EvidenceKind.BOOLEAN
    required: bool = True


class Questionnaire(AtlasModel):

    questionnaire_id: str
    title: str
    tier: EvidenceTier = EvidenceTier.TIER_2
    questions: list[Question] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_question_ids(self) -> Questionnaire:
        ids = [q.question_id for q in self.questions]
        if len(ids) != len(set(ids)):
            raise ValueError("questionnaire has duplicate question_id")
        return self

    @model_validator(mode="after")
    def _tier_is_internal(self) -> Questionnaire:
        if self.tier not in {EvidenceTier.TIER_2, EvidenceTier.TIER_3}:
            raise ValueError("questionnaire tier must be TIER_2 or TIER_3, never Tier-1")
        return self

    def question_index(self) -> dict[str, Question]:
        return {q.question_id: q for q in self.questions}


class Answer(AtlasModel):

    question_id: str
    compliant: bool
    content: str = Field(default="", description="uploaded evidence content or note")


class QuestionnaireResponse(AtlasModel):

    questionnaire_id: str
    respondent: str = Field(min_length=1)
    consent_ref: str = Field(min_length=1, description="non-empty consent provenance")
    answers: list[Answer] = Field(default_factory=list)


class QuestionnaireError(ValueError):
    pass


class QuestionnaireEngine:

    def validate(self, questionnaire: Questionnaire, response: QuestionnaireResponse) -> None:
        if response.questionnaire_id != questionnaire.questionnaire_id:
            raise QuestionnaireError("response questionnaire_id does not match the questionnaire")
        index = questionnaire.question_index()
        seen: set[str] = set()
        for answer in response.answers:
            if answer.question_id not in index:
                raise QuestionnaireError(f"answer to unknown question {answer.question_id!r}")
            if answer.question_id in seen:
                raise QuestionnaireError(f"duplicate answer for question {answer.question_id!r}")
            seen.add(answer.question_id)
        missing = [q.question_id for q in questionnaire.questions if q.required and q.question_id not in seen]
        if missing:
            raise QuestionnaireError(f"missing answers for required questions: {missing}")

    def evidence(
        self,
        questionnaire: Questionnaire,
        response: QuestionnaireResponse,
        *,
        now: datetime | None = None,
    ) -> list[Evidence]:
        self.validate(questionnaire, response)
        index = questionnaire.question_index()
        timestamp = now or _utcnow()
        records: list[Evidence] = []
        for answer in response.answers:
            question = index[answer.question_id]
            if question.evidence_kind is EvidenceKind.UPLOAD and answer.content:
                records.append(
                    Evidence(
                        evidence_id=self._evidence_id(questionnaire.questionnaire_id, answer.question_id),
                        control_id=question.control_id,
                        evidence_tier=questionnaire.tier,
                        content_hash=content_hash(answer.content),
                        source=f"questionnaire:{response.respondent}",
                        timestamp=timestamp,
                        consent_ref=response.consent_ref,
                    )
                )
        return records

    @staticmethod
    def _evidence_id(questionnaire_id: str, question_id: str) -> str:
        return f"ev:{questionnaire_id}:{question_id}"

    def assessments(
        self, questionnaire: Questionnaire, response: QuestionnaireResponse
    ) -> list[ControlAssessment]:
        self.validate(questionnaire, response)
        answered = {a.question_id: a for a in response.answers}
        out: list[ControlAssessment] = []
        for question in questionnaire.questions:
            answer = answered.get(question.question_id)
            if answer is None:
                status = ComplianceStatus.NOT_ASSESSED
            elif answer.compliant:
                status = ComplianceStatus.COMPLIANT
            else:
                status = ComplianceStatus.NON_COMPLIANT
            has_upload = (
                answer is not None and question.evidence_kind is EvidenceKind.UPLOAD and bool(answer.content)
            )
            evidence_ids = (
                [self._evidence_id(questionnaire.questionnaire_id, question.question_id)]
                if has_upload
                else []
            )
            out.append(
                ControlAssessment(
                    control_id=question.control_id,
                    tier=questionnaire.tier,
                    status=status,
                    evidence_ids=evidence_ids,
                    source="questionnaire",
                )
            )
        return out
