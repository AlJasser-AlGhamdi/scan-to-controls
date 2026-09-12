from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from p2c.schemas.enums import EvidenceTier, Framework, ScanIntensity, Severity


def _ensure_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(_ensure_utc)]

_CVSS_MIN = 0.0
_CVSS_MAX = 10.0
_BAND_LOW_MAX = 4.0
_BAND_MEDIUM_MAX = 7.0
_BAND_HIGH_MAX = 9.0


def severity_from_cvss(score: float) -> Severity:
    if not _CVSS_MIN <= score <= _CVSS_MAX:
        raise ValueError(f"CVSS base score {score!r} outside [0.0, 10.0]")
    if score == _CVSS_MIN:
        return Severity.NONE
    if score < _BAND_LOW_MAX:
        return Severity.LOW
    if score < _BAND_MEDIUM_MAX:
        return Severity.MEDIUM
    if score < _BAND_HIGH_MAX:
        return Severity.HIGH
    return Severity.CRITICAL


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AtlasModel(BaseModel):

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        use_enum_values=False,
        ser_json_timedelta="iso8601",
    )


class Asset(AtlasModel):

    asset_id: str
    value: str = Field(description="domain, subdomain, IP, or URL")
    asset_type: str = Field(description="e.g. domain|subdomain|ip|url|service")
    source_tool: str
    tool_version: str
    discovery_method: str = Field(description="e.g. subfinder|amass|crt.sh|dnsx|synthetic")
    consent_ref: str
    first_seen: UtcDateTime = Field(default_factory=_utcnow)
    attributes: dict[str, Any] = Field(default_factory=dict)


class Finding(AtlasModel):
    finding_id: str
    asset: str = Field(description="reference to Asset.asset_id (or asset value)")
    source_tool: str
    tool_version: str
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    observed_state: str
    cvss_v3_1_vector: str | None = None
    cvss_base_score: float | None = Field(default=None, ge=_CVSS_MIN, le=_CVSS_MAX)
    severity: Severity
    control_ids: list[str] = Field(default_factory=list)
    evidence_tier: EvidenceTier
    timestamp: UtcDateTime = Field(default_factory=_utcnow)
    consent_ref: str

    @model_validator(mode="after")
    def _severity_matches_score(self) -> Finding:
        if self.cvss_base_score is not None:
            expected = severity_from_cvss(self.cvss_base_score)
            if self.severity is not expected:
                raise ValueError(
                    f"severity {self.severity} inconsistent with CVSS "
                    f"{self.cvss_base_score} (expected {expected})"
                )
        return self


class Control(AtlasModel):
    control_id: str = Field(description="native scheme, e.g. 2-5-3-1")
    framework: Framework
    title_en: str
    title_ar: str
    domain: str
    subdomain: str
    evidence_tier: EvidenceTier
    class_a_applicable: bool = True
    class_b_applicable: bool = False


class Evidence(AtlasModel):

    evidence_id: str
    control_id: str
    evidence_tier: EvidenceTier
    content_hash: str = Field(description="sha256 hex of the canonical content")
    source: str
    finding_ids: list[str] = Field(default_factory=list)
    timestamp: UtcDateTime = Field(default_factory=_utcnow)
    consent_ref: str


class Consent(AtlasModel):
    consent_id: str
    verified_apex: str
    in_scope_subdomains: list[str] = Field(default_factory=list)
    in_scope_ip_ranges: list[str] = Field(default_factory=list)
    time_window_start: UtcDateTime
    time_window_end: UtcDateTime
    allowed_intensity: ScanIntensity = ScanIntensity.PASSIVE
    verification_method: str = Field(description="dns-txt|html-file|meta-tag")
    verified_at: UtcDateTime = Field(default_factory=_utcnow)
    content_hash: str | None = None

    @model_validator(mode="after")
    def _window_ordered(self) -> Consent:
        if self.time_window_end <= self.time_window_start:
            raise ValueError("time_window_end must be after time_window_start")
        return self

    def is_active(self, at: datetime | None = None) -> bool:
        now = _ensure_utc(at) if at is not None else _utcnow()
        return self.time_window_start <= now <= self.time_window_end


class Attestation(AtlasModel):

    attestation_id: str
    control_id: str
    statement: str
    signer_identity: str
    payload_hash: str
    valid_from: UtcDateTime
    valid_until: UtcDateTime
    signature: str | None = None
    timestamp_token: str | None = Field(default=None, description="RFC-3161 TSA token (base64)")
    timestamp: UtcDateTime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _validity_ordered(self) -> Attestation:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


class Score(AtlasModel):
    subject_id: str
    assessed_score: float = Field(ge=0.0, le=1.0)
    documented_score: float = Field(ge=0.0, le=1.0)
    gap: float = Field(default=0.0, ge=0.0, le=1.0)
    tier1_controls: int = Field(default=0, ge=0)
    total_controls: int = Field(default=0, ge=0)
    contradiction_count: int = Field(default=0, ge=0)
    timestamp: UtcDateTime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _derive_gap(self) -> Score:
        object.__setattr__(self, "gap", round(1.0 - self.assessed_score, 12))
        return self
