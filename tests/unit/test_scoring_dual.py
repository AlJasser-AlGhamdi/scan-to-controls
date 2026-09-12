from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from p2c.schemas.enums import EvidenceTier
from p2c.scoring.assemble import merge_assessments
from p2c.scoring.contradictions import control_related
from p2c.scoring.dual_score import apply_weights, compute_dual_score, reconcile
from p2c.scoring.models import ComplianceStatus, ControlAssessment

_STATUSES = list(ComplianceStatus)
_TIERS = [EvidenceTier.TIER_1, EvidenceTier.TIER_2, EvidenceTier.TIER_3]


def _mk(cid: str, tier: EvidenceTier, status: ComplianceStatus, weight: float = 1.0) -> ControlAssessment:
    return ControlAssessment(control_id=cid, tier=tier, status=status, weight=weight)


def test_assessed_covers_only_tier1() -> None:
    assessments = [
        _mk("2-8-3-3", EvidenceTier.TIER_1, ComplianceStatus.COMPLIANT),
        _mk("2-4-3-5", EvidenceTier.TIER_1, ComplianceStatus.NON_COMPLIANT),
        _mk("1-3-4", EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT),
    ]
    score = compute_dual_score(assessments)
    assert score.assessed_score == 0.5
    assert score.gap == 0.5
    assert score.documented_score == 2 / 3


def test_attestation_cannot_lift_assessed_score() -> None:
    base = [_mk("2-8-3-3", EvidenceTier.TIER_1, ComplianceStatus.NON_COMPLIANT)]
    with_attestation = [*base, _mk("2-8-3-3-att", EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT)]
    assert compute_dual_score(with_attestation).assessed_score == 0.0
    assert compute_dual_score(with_attestation).documented_score > 0.0


def test_empty_assessment_set_scores_zero() -> None:
    score = compute_dual_score([])
    assert score.assessed_score == 0.0
    assert score.documented_score == 0.0
    assert score.gap == 1.0


def test_weights_change_the_score() -> None:
    assessments = [
        _mk("2-1-1", EvidenceTier.TIER_1, ComplianceStatus.COMPLIANT, weight=3.0),
        _mk("2-2-1", EvidenceTier.TIER_1, ComplianceStatus.NON_COMPLIANT, weight=1.0),
    ]
    assert compute_dual_score(assessments).assessed_score == 0.75


def test_apply_weights_distributes_group_weight() -> None:
    assessments = [
        _mk("2-1-1", EvidenceTier.TIER_1, ComplianceStatus.COMPLIANT),
        _mk("2-2-1", EvidenceTier.TIER_1, ComplianceStatus.COMPLIANT),
        _mk("1-1-1", EvidenceTier.TIER_1, ComplianceStatus.COMPLIANT),
    ]
    weighted = apply_weights(assessments, {"2": 0.8, "1": 0.2}, key="domain")
    by = {a.control_id: a.weight for a in weighted}
    assert by["2-1-1"] == 0.4 and by["2-2-1"] == 0.4
    assert by["1-1-1"] == 0.2
    assert [a.control_id for a in weighted] == [a.control_id for a in assessments]


def test_apply_weights_counts_distinct_controls_not_assessments() -> None:
    assessments = [
        _mk("2-1-1", EvidenceTier.TIER_1, ComplianceStatus.COMPLIANT),
        _mk("2-1-1", EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT),
        _mk("1-1-1", EvidenceTier.TIER_1, ComplianceStatus.NON_COMPLIANT),
    ]
    weighted = apply_weights(assessments, {"2": 0.9, "1": 0.1}, key="domain")
    by = {a.control_id: a.weight for a in weighted}
    assert by["2-1-1"] == 0.9
    assert by["1-1-1"] == 0.1
    assert compute_dual_score(weighted).assessed_score == pytest.approx(0.9)


def test_apply_weights_keeps_default_for_ungrouped_controls() -> None:
    assessments = [_mk("2-1-1", EvidenceTier.TIER_1, ComplianceStatus.COMPLIANT)]
    weighted = apply_weights(assessments, {"9": 0.5}, key="domain")
    assert weighted[0].weight == 1.0


def test_apply_weights_rejects_unknown_key() -> None:
    with pytest.raises(ValueError, match="unknown group key"):
        apply_weights([_mk("2-1-1", EvidenceTier.TIER_1, ComplianceStatus.COMPLIANT)], {}, key="galaxy")


def test_apply_weights_rejects_nonpositive_group_weight() -> None:
    a = [_mk("2-1-1", EvidenceTier.TIER_1, ComplianceStatus.COMPLIANT)]
    with pytest.raises(ValueError, match="must be positive"):
        apply_weights(a, {"2": 0.0})
    with pytest.raises(ValueError, match="must be positive"):
        apply_weights(a, {"2": -0.5})


def test_duplicate_control_ids_are_reconciled_not_double_counted() -> None:
    dup = [
        _mk("2-8-3-3", EvidenceTier.TIER_1, ComplianceStatus.NON_COMPLIANT),
        _mk("2-8-3-3", EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT),
    ]
    score = compute_dual_score(dup)
    assert score.documented_total_weight == 1.0
    assert score.documented_score == 0.0
    assert score.assessed_score == 0.0


def test_reconcile_tie_prefers_non_compliant() -> None:
    both_orders = [
        [
            _mk("2-2-1", EvidenceTier.TIER_2, ComplianceStatus.COMPLIANT),
            _mk("2-2-1", EvidenceTier.TIER_2, ComplianceStatus.NON_COMPLIANT),
        ],
        [
            _mk("2-2-1", EvidenceTier.TIER_2, ComplianceStatus.NON_COMPLIANT),
            _mk("2-2-1", EvidenceTier.TIER_2, ComplianceStatus.COMPLIANT),
        ],
    ]
    for group in both_orders:
        (winner,) = reconcile(group)
        assert winner.status is ComplianceStatus.NON_COMPLIANT


_assessment_strategy = st.builds(
    _mk,
    cid=st.integers(min_value=0, max_value=999).map(lambda i: f"c-{i}"),
    tier=st.sampled_from(_TIERS),
    status=st.sampled_from(_STATUSES),
    weight=st.floats(min_value=0.01, max_value=100.0, allow_nan=False, allow_infinity=False),
)


@given(st.lists(_assessment_strategy, max_size=40))
def test_scores_always_in_unit_interval(assessments: list[ControlAssessment]) -> None:
    unique = list({a.control_id: a for a in assessments}.values())
    score = compute_dual_score(unique)
    assert 0.0 <= score.assessed_score <= 1.0
    assert 0.0 <= score.documented_score <= 1.0
    assert 0.0 <= score.gap <= 1.0
    assert score.gap == 1.0 - score.assessed_score


@given(st.lists(_assessment_strategy, min_size=1, max_size=40), st.integers())
def test_tier1_pass_to_fail_never_increases_assessed(assessments: list[ControlAssessment], pick: int) -> None:
    unique = list({a.control_id: a for a in assessments}.values())
    before = compute_dual_score(unique).assessed_score
    tier1_idx = [i for i, a in enumerate(unique) if a.tier == 1 and a.satisfied]
    if not tier1_idx:
        return
    i = tier1_idx[pick % len(tier1_idx)]
    flipped = list(unique)
    flipped[i] = flipped[i].model_copy(update={"status": ComplianceStatus.NON_COMPLIANT})
    after = compute_dual_score(flipped).assessed_score
    assert after <= before + 1e-12


@given(st.lists(_assessment_strategy, min_size=1, max_size=40), st.integers())
def test_adding_evidence_never_decreases_documented(assessments: list[ControlAssessment], pick: int) -> None:
    unique = list({a.control_id: a for a in assessments}.values())
    before = compute_dual_score(unique).documented_score
    not_satisfied = [i for i, a in enumerate(unique) if not a.satisfied]
    if not_satisfied:
        i = not_satisfied[pick % len(not_satisfied)]
        upgraded = list(unique)
        upgraded[i] = upgraded[i].model_copy(update={"status": ComplianceStatus.COMPLIANT})
        after = compute_dual_score(upgraded).documented_score
        assert after >= before - 1e-12


_FAMILIES = [
    ("2-4-3", "2-4-3-5"),
    ("2-8-3", "2-8-3-3"),
    ("2-5-3", "2-5-3-1", "2-5-3-2"),
    ("1-3", "1-3-2"),
]
_HIER_IDS = [cid for fam in _FAMILIES for cid in fam] + ["3-1-1", "4-2-3-1"]
_HIER_WEIGHTS = {cid: 1.0 + (i % 5) * 0.5 for i, cid in enumerate(_HIER_IDS)}


@st.composite
def _hier_assessment(draw: st.DrawFn) -> ControlAssessment:
    cid = draw(st.sampled_from(_HIER_IDS))
    return _mk(
        cid, draw(st.sampled_from(_TIERS)), draw(st.sampled_from(_STATUSES)), weight=_HIER_WEIGHTS[cid]
    )


@given(st.lists(_hier_assessment(), max_size=30))
def test_refuted_higher_tier_never_survives_as_compliant(assessments: list[ControlAssessment]) -> None:
    merged = merge_assessments(assessments)
    tier1_nc = {
        a.control_id
        for a in assessments
        if a.tier == EvidenceTier.TIER_1 and a.status == ComplianceStatus.NON_COMPLIANT
    }
    for m in merged:
        if m.tier != EvidenceTier.TIER_1 and m.status == ComplianceStatus.COMPLIANT:
            assert not any(control_related(m.control_id, nc) for nc in tier1_nc), (
                f"{m.control_id} stayed compliant despite a Tier-1 refutation"
            )


@given(st.lists(_hier_assessment(), min_size=1, max_size=25), st.sampled_from(_HIER_IDS))
def test_refuted_attestation_cannot_raise_documented(base: list[ControlAssessment], att_control: str) -> None:
    tier1_nc = [
        a.control_id
        for a in base
        if a.tier == EvidenceTier.TIER_1 and a.status == ComplianceStatus.NON_COMPLIANT
    ]
    if not any(control_related(att_control, nc) for nc in tier1_nc):
        return
    attestation = _mk(
        att_control, EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT, weight=_HIER_WEIGHTS[att_control]
    )
    without = compute_dual_score(merge_assessments(base)).documented_score
    with_att = compute_dual_score(merge_assessments(base, [attestation])).documented_score
    assert with_att <= without + 1e-12
