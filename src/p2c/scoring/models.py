from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import AtlasModel, UtcDateTime, _utcnow


class ComplianceStatus(StrEnum):

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_ASSESSED = "not_assessed"


class ControlAssessment(AtlasModel):

    control_id: str
    tier: EvidenceTier
    status: ComplianceStatus
    weight: float = Field(default=1.0, gt=0.0)
    evidence_ids: list[str] = Field(default_factory=list)
    source: str = Field(default="", description="finding | questionnaire | attestation")

    @property
    def satisfied(self) -> bool:
        return self.status is ComplianceStatus.COMPLIANT


class DualScore(AtlasModel):

    assessed_score: float = Field(ge=0.0, le=1.0, description="weighted Tier-1 compliance")
    documented_score: float = Field(ge=0.0, le=1.0, description="weighted all-tier compliance")
    gap: float = Field(ge=0.0, le=1.0, description="externally-attributable gap G = 1 - assessed")
    tier1_total_weight: float = Field(ge=0.0)
    tier1_compliant_weight: float = Field(ge=0.0)
    documented_total_weight: float = Field(ge=0.0)
    documented_satisfied_weight: float = Field(ge=0.0)
    weights_source: str = "uniform"
    computed_at: UtcDateTime = Field(default_factory=_utcnow)


class Contradiction(AtlasModel):

    control_id: str
    attestation_id: str
    finding_id: str
    attested_claim: str
    observed_state: str
    detail: str = ""
