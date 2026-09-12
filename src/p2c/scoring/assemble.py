from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from p2c.mapping.models import ControlMapping
from p2c.scanning.catalog import CATALOG as _CHECK_CATALOG
from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import Attestation
from p2c.scoring.contradictions import control_related
from p2c.scoring.dual_score import reconcile
from p2c.scoring.models import ComplianceStatus, ControlAssessment

TIER1_CHECKABLE: frozenset[str] = frozenset(
    cid for spec in _CHECK_CATALOG.values() for cid in spec.control_ids
)


def tier1_assessments(
    mappings: Sequence[ControlMapping], *, checkable: frozenset[str] = TIER1_CHECKABLE
) -> list[ControlAssessment]:
    non_compliant = {m.control_id for m in mappings if m.tier == 1}
    out: list[ControlAssessment] = []
    for cid in sorted(checkable | non_compliant):
        status = ComplianceStatus.NON_COMPLIANT if cid in non_compliant else ComplianceStatus.COMPLIANT
        out.append(
            ControlAssessment(control_id=cid, tier=EvidenceTier.TIER_1, status=status, source="finding")
        )
    return out


def attestation_assessments(
    attestations: Sequence[Attestation], *, now: datetime | None = None
) -> list[ControlAssessment]:
    at = now or datetime.now(UTC)
    return [
        ControlAssessment(
            control_id=a.control_id,
            tier=EvidenceTier.TIER_3,
            status=ComplianceStatus.COMPLIANT,
            evidence_ids=[a.attestation_id],
            source="attestation",
        )
        for a in attestations
        if a.valid_from <= at <= a.valid_until
    ]


def _neutralize_refuted(assessments: list[ControlAssessment]) -> list[ControlAssessment]:
    tier1_nc = [
        a.control_id
        for a in assessments
        if a.tier == EvidenceTier.TIER_1 and a.status == ComplianceStatus.NON_COMPLIANT
    ]
    if not tier1_nc:
        return assessments
    out: list[ControlAssessment] = []
    for a in assessments:
        refuted = (
            a.tier != EvidenceTier.TIER_1
            and a.status == ComplianceStatus.COMPLIANT
            and any(control_related(a.control_id, nc) for nc in tier1_nc)
        )
        out.append(a.model_copy(update={"status": ComplianceStatus.NON_COMPLIANT}) if refuted else a)
    return out


def merge_assessments(*groups: Sequence[ControlAssessment]) -> list[ControlAssessment]:
    return _neutralize_refuted(reconcile([assessment for group in groups for assessment in group]))
