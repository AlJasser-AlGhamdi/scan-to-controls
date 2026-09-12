from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from p2c.scoring.models import ComplianceStatus, ControlAssessment, DualScore


def _supersedes(new: ControlAssessment, current: ControlAssessment) -> bool:
    if new.tier != current.tier:
        return new.tier < current.tier
    new_unassessed = new.status is ComplianceStatus.NOT_ASSESSED
    current_unassessed = current.status is ComplianceStatus.NOT_ASSESSED
    if new_unassessed != current_unassessed:
        return current_unassessed
    return current.satisfied and not new.satisfied


def reconcile(assessments: Iterable[ControlAssessment]) -> list[ControlAssessment]:
    best: dict[str, ControlAssessment] = {}
    for a in assessments:
        current = best.get(a.control_id)
        if current is None or _supersedes(a, current):
            best[a.control_id] = a
    return [best[cid] for cid in sorted(best)]


def _weighted(assessments: Iterable[ControlAssessment]) -> tuple[float, float]:
    total = 0.0
    satisfied = 0.0
    for a in assessments:
        total += a.weight
        if a.satisfied:
            satisfied += a.weight
    return satisfied, total


def compute_dual_score(
    assessments: Sequence[ControlAssessment], *, weights_source: str = "uniform"
) -> DualScore:
    assessments = reconcile(assessments)
    tier1 = [a for a in assessments if a.tier == 1]
    tier1_compliant, tier1_total = _weighted(tier1)
    documented_satisfied, documented_total = _weighted(assessments)

    assessed = tier1_compliant / tier1_total if tier1_total > 0 else 0.0
    documented = documented_satisfied / documented_total if documented_total > 0 else 0.0
    return DualScore(
        assessed_score=assessed,
        documented_score=documented,
        gap=1.0 - assessed,
        tier1_total_weight=tier1_total,
        tier1_compliant_weight=tier1_compliant,
        documented_total_weight=documented_total,
        documented_satisfied_weight=documented_satisfied,
        weights_source=weights_source,
    )


def apply_weights(
    assessments: Sequence[ControlAssessment], group_weights: Mapping[str, float], *, key: str = "domain"
) -> list[ControlAssessment]:
    bad = {g: w for g, w in group_weights.items() if w <= 0}
    if bad:
        raise ValueError(f"group weights must be positive, got {bad}")

    group_ids: dict[str, set[str]] = {}
    for a in assessments:
        group_ids.setdefault(_group_of(a.control_id, key), set()).add(a.control_id)

    out: list[ControlAssessment] = []
    for a in assessments:
        group = _group_of(a.control_id, key)
        share = group_weights.get(group)
        weight = (share / len(group_ids[group])) if share is not None else 1.0
        out.append(a.model_copy(update={"weight": weight}))
    return out


def _group_of(control_id: str, key: str) -> str:
    parts = control_id.split("-")
    if key == "domain":
        return parts[0]
    if key == "subdomain":
        return "-".join(parts[:2])
    raise ValueError(f"unknown group key {key!r} (want 'domain' or 'subdomain')")
