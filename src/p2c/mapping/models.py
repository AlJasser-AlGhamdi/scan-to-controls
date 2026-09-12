from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from p2c.schemas.enums import EvidenceTier, Severity
from p2c.schemas.models import AtlasModel, UtcDateTime, _utcnow


class MappingMethod(StrEnum):

    DETERMINISTIC = "deterministic"
    TRIAGE = "triage"


class ControlMapping(AtlasModel):

    control_id: str = Field(description="native scheme, e.g. 2-5-3-1")
    framework: str = Field(description="ecc | ncnicc")
    tier: EvidenceTier
    finding_id: str
    asset: str
    severity: Severity
    method: MappingMethod
    confidence: float = Field(ge=0.0, le=1.0)
    rule_id: str | None = None
    rationale: str = ""
    remediation: str = ""
    reviewer_note: str = ""
    ncnicc_class_a: str | None = Field(default=None, description="NCNICC sub-component, e.g. 4-2")
    ncnicc_class_b: str | None = Field(default=None, description="NCNICC sub-component, e.g. 4-2")
    ncnicc_class_a_status: str | None = Field(default=None, description="M | R for Class A")
    ncnicc_class_b_status: str | None = Field(default=None, description="M | R for Class B (SME tier)")
    needs_confirmation: bool = False
    timestamp: UtcDateTime = Field(default_factory=_utcnow)
