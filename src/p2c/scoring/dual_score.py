from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence

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
    assessments: Sequence[ControlAssessment],
    *,
    weights_source: str = "uniform",
    universe: Collection[str] | None = None,
) -> DualScore:
    recorded_gap = {a.control_id for a in assessments if a.tier > 1 and a.status is ComplianceStatus.NON_COMPLIANT}
    assessments = reconcile(assessments)

    def passes(a: ControlAssessment) -> bool:
        return a.satisfied and not (a.tier == 1 and a.control_id in recorded_gap)

    tier1 = [a for a in assessments if a.tier == 1]
    tier1_compliant, tier1_total = _weighted(tier1)
    tier1_observed = 0.0
    for a in tier1:
        if a.status is not ComplianceStatus.NOT_ASSESSED:
            tier1_observed += a.weight

    if universe is not None:
        if any(a.weight != 1.0 for a in assessments):
            raise ValueError(
                "a fixed documented set needs uniform weights: an unevidenced row has no group to take "
                "a share from, so weighted scoring over a universe could reward withholding evidence"
            )
        rows = set(universe)
        in_set = [a for a in assessments if a.control_id in rows]
        documented_satisfied = float(sum(1 for a in in_set if passes(a)))
        documented_total = float(len(rows))
        evidenced = float(sum(1 for a in in_set if a.status is not ComplianceStatus.NOT_ASSESSED))
    else:
        documented_total = 0.0
        documented_satisfied = 0.0
        for a in assessments:
            documented_total += a.weight
            if passes(a):
                documented_satisfied += a.weight
        evidenced = 0.0
        for a in assessments:
            if a.status is not ComplianceStatus.NOT_ASSESSED:
                evidenced += a.weight

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
        coverage=tier1_observed / tier1_total if tier1_total > 0 else 0.0,
        evidence_coverage=evidenced / documented_total if documented_total > 0 else 0.0,
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
