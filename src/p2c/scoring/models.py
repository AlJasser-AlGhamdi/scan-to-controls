from __future__ import annotations

from enum import StrEnum

from pydantic import Field, computed_field, model_validator

from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import AtlasModel, UtcDateTime, _utcnow


class ComplianceStatus(StrEnum):

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_ASSESSED = "not_assessed"


class ObservationState(StrEnum):

    VIOLATION_OBSERVED = "violation_observed"
    NO_VIOLATION_OBSERVED = "no_violation_observed"
    NOT_OBSERVED = "not_observed"


_OBSERVATION_OF: dict[ComplianceStatus, ObservationState] = {
    ComplianceStatus.NON_COMPLIANT: ObservationState.VIOLATION_OBSERVED,
    ComplianceStatus.COMPLIANT: ObservationState.NO_VIOLATION_OBSERVED,
    ComplianceStatus.NOT_ASSESSED: ObservationState.NOT_OBSERVED,
}


class ControlAssessment(AtlasModel):

    control_id: str
    tier: EvidenceTier
    status: ComplianceStatus
    weight: float = Field(default=1.0, gt=0.0)
    evidence_ids: list[str] = Field(default_factory=list)
    source: str = Field(default="", description="finding | questionnaire | attestation")

    @model_validator(mode="before")
    @classmethod
    def _drop_derived_observation(cls, data: object) -> object:
        if isinstance(data, dict) and "observation" in data:
            data = {k: v for k, v in data.items() if k != "observation"}
        return data

    @property
    def satisfied(self) -> bool:
        return self.status is ComplianceStatus.COMPLIANT

    @computed_field
    @property
    def observation(self) -> ObservationState | None:
        return _OBSERVATION_OF[self.status] if self.tier == EvidenceTier.TIER_1 else None


class DualScore(AtlasModel):

    assessed_score: float = Field(ge=0.0, le=1.0, description="weighted Tier-1 compliance")
    documented_score: float = Field(ge=0.0, le=1.0, description="weighted all-tier compliance")
    gap: float = Field(
        ge=0.0, le=1.0, description="1 - assessed: the Tier-1 share not observed clean (violated or unread)"
    )
    tier1_total_weight: float = Field(ge=0.0)
    tier1_compliant_weight: float = Field(ge=0.0)
    documented_total_weight: float = Field(ge=0.0)
    documented_satisfied_weight: float = Field(ge=0.0)
    coverage: float = Field(ge=0.0, le=1.0, description="share of the Tier-1 weight the scan observed")
    evidence_coverage: float = Field(
        ge=0.0, le=1.0, description="share of the documented set that carries assessed evidence"
    )
    weights_source: str = "uniform"
    computed_at: UtcDateTime = Field(default_factory=_utcnow)


class Contradiction(AtlasModel):

    control_id: str
    attestation_id: str
    finding_id: str
    attested_claim: str
    observed_state: str
    tier: int = Field(default=3, ge=2, le=3, description="evidence tier of the refuted claim")
    detail: str = ""
