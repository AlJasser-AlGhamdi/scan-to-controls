from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

import structlog

from p2c.mapping.models import ControlMapping
from p2c.schemas.enums import Severity
from p2c.schemas.models import Attestation
from p2c.scoring.models import Contradiction

log = structlog.get_logger("p2c.scoring.contradictions")

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.NONE: 4,
}


def control_related(attested: str, finding: str) -> bool:
    return attested == finding or finding.startswith(f"{attested}-") or attested.startswith(f"{finding}-")


def detect_contradictions(
    attestations: Sequence[Attestation],
    tier1_findings: Sequence[ControlMapping],
    *,
    now: datetime | None = None,
) -> list[Contradiction]:
    tier1 = [m for m in tier1_findings if m.tier == 1]
    considered = (
        [a for a in attestations if a.valid_from <= now <= a.valid_until]
        if now is not None
        else list(attestations)
    )

    contradictions: list[Contradiction] = []
    for attestation in considered:
        refuting = [m for m in tier1 if control_related(attestation.control_id, m.control_id)]
        if not refuting:
            continue
        finding = min(refuting, key=lambda m: (_SEVERITY_RANK[m.severity], m.finding_id))
        contradictions.append(
            Contradiction(
                control_id=attestation.control_id,
                attestation_id=attestation.attestation_id,
                finding_id=finding.finding_id,
                attested_claim=attestation.statement,
                observed_state=f"Tier-1 finding {finding.finding_id} ({finding.severity.value})",
                detail=(
                    f"attestation claims compliance for {attestation.control_id}, "
                    f"but a Tier-1 scan finding refutes it"
                ),
            )
        )
        log.warning(
            "attestation_contradicts_evidence",
            control_id=attestation.control_id,
            attestation_id=attestation.attestation_id,
            finding_id=finding.finding_id,
        )
    contradictions.sort(key=lambda c: (c.control_id, c.attestation_id))
    return contradictions
