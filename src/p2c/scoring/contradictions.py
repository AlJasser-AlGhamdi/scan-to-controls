from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

import structlog

from p2c.mapping.models import ControlMapping
from p2c.schemas.enums import Severity
from p2c.schemas.models import Attestation
from p2c.scoring.models import ComplianceStatus, Contradiction, ControlAssessment

log = structlog.get_logger("p2c.scoring.contradictions")

_TIER2_CLAIM = "internal assessment record: compliant"

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.NONE: 4,
}


IMPLEMENTS: dict[str, str] = {
    "2-3-2": "2-3-3",
    "2-4-2": "2-4-3",
    "2-5-2": "2-5-3",
    "2-7-2": "2-7-1",
    "2-8-2": "2-8-3",
    "2-10-2": "2-10-3",
    "2-15-2": "2-15-3",
}


def hierarchy_related(attested: str, finding: str) -> bool:
    return attested == finding or finding.startswith(f"{attested}-")


def control_related(attested: str, finding: str) -> bool:
    listed = IMPLEMENTS.get(attested)
    return hierarchy_related(attested, finding) or (listed is not None and hierarchy_related(listed, finding))


def detect_contradictions(
    attestations: Sequence[Attestation],
    tier1_findings: Sequence[ControlMapping],
    *,
    now: datetime | None = None,
    tier2: Sequence[ControlAssessment] = (),
) -> list[Contradiction]:
    tier1 = [m for m in tier1_findings if m.tier == 1]
    considered = (
        [a for a in attestations if a.valid_from <= now <= a.valid_until]
        if now is not None
        else list(attestations)
    )
    claims: list[tuple[str, str, str, int]] = [
        (a.control_id, a.attestation_id, a.statement, 3) for a in considered
    ]
    claims += [
        (r.control_id, r.evidence_ids[0] if r.evidence_ids else f"tier2:{r.control_id}", _TIER2_CLAIM, 2)
        for r in tier2
        if r.status is ComplianceStatus.COMPLIANT
    ]

    contradictions: list[Contradiction] = []
    for control_id, claim_id, statement, tier in claims:
        refuting = [m for m in tier1 if control_related(control_id, m.control_id)]
        if not refuting:
            continue
        finding = min(refuting, key=lambda m: (_SEVERITY_RANK[m.severity], m.finding_id))
        contradictions.append(
            Contradiction(
                control_id=control_id,
                attestation_id=claim_id,
                finding_id=finding.finding_id,
                attested_claim=statement,
                observed_state=f"Tier-1 finding {finding.finding_id} ({finding.severity.value})",
                tier=tier,
                detail=(
                    f"Tier-{tier} claim of compliance for {control_id}, but a Tier-1 scan finding refutes it"
                ),
            )
        )
        log.warning(
            "attestation_contradicts_evidence",
            control_id=control_id,
            attestation_id=claim_id,
            finding_id=finding.finding_id,
            tier=tier,
        )
    contradictions.sort(key=lambda c: (c.control_id, c.tier, c.attestation_id))
    return contradictions
