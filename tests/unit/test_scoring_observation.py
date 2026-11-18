from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from p2c.mapping.rules import MappingEngine
from p2c.scanning.catalog import CheckId, build_finding
from p2c.schemas.enums import EvidenceTier
from p2c.scoring.assemble import TIER1_CHECKABLE, merge_assessments, tier1_assessments
from p2c.scoring.dual_score import compute_dual_score
from p2c.scoring.models import ComplianceStatus, ControlAssessment, ObservationState

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _mappings(*checks: CheckId):
    findings = [
        build_finding(
            c,
            asset="x.example",
            observed_state="o",
            consent_ref="C",
            source_tool="s",
            tool_version="0",
            now=NOW,
        )
        for c in checks
    ]
    return MappingEngine().map_findings(findings)


def test_unobserved_control_is_not_assessed_and_never_passes() -> None:
    t1 = {a.control_id: a for a in tier1_assessments([], unobserved=frozenset({"2-8-3-3"}))}
    assert t1["2-8-3-3"].status is ComplianceStatus.NOT_ASSESSED
    assert t1["2-8-3-3"].observation is ObservationState.NOT_OBSERVED
    assert not t1["2-8-3-3"].satisfied


def test_a_finding_outranks_non_observation() -> None:
    mappings = _mappings(CheckId.SPF_MISSING)
    t1 = {a.control_id: a for a in tier1_assessments(mappings, unobserved=frozenset({"2-4-3-5"}))}
    assert t1["2-4-3-5"].status is ComplianceStatus.NON_COMPLIANT
    assert t1["2-4-3-5"].observation is ObservationState.VIOLATION_OBSERVED


def test_observed_clean_control_reads_no_violation_observed() -> None:
    t1 = {a.control_id: a for a in tier1_assessments([], unobserved=frozenset())}
    assert t1["2-8-3-3"].observation is ObservationState.NO_VIOLATION_OBSERVED
    t3 = ControlAssessment(control_id="1-3-2", tier=EvidenceTier.TIER_3, status=ComplianceStatus.COMPLIANT)
    assert t3.observation is None


def test_an_unobserved_estate_scores_zero_with_zero_coverage() -> None:
    score = compute_dual_score(tier1_assessments([], unobserved=TIER1_CHECKABLE))
    assert score.assessed_score == 0.0
    assert score.coverage == 0.0


def test_coverage_counts_observed_controls_of_either_outcome() -> None:
    mappings = _mappings(CheckId.SPF_MISSING)
    unobserved = frozenset({"2-8-3-3", "2-4-3-5"})
    score = compute_dual_score(tier1_assessments(mappings, unobserved=unobserved))
    n = len(TIER1_CHECKABLE)
    assert score.coverage == (n - 1) / n
    assert score.assessed_score == (n - 2) / n


def test_a_self_report_cannot_pass_an_unobserved_externally_testable_control() -> None:
    claim = ControlAssessment(
        control_id="2-8-3-3", tier=EvidenceTier.TIER_2, status=ComplianceStatus.COMPLIANT
    )
    merged = merge_assessments(tier1_assessments([], unobserved=frozenset({"2-8-3-3"})), [claim])
    record = next(a for a in merged if a.control_id == "2-8-3-3")
    assert record.tier == EvidenceTier.TIER_1
    assert not record.satisfied


def test_observation_state_is_serialised() -> None:
    a = tier1_assessments([], unobserved=frozenset({"2-8-3-3"}))
    dumped = {d["control_id"]: d for d in (x.model_dump(mode="json") for x in a)}
    assert dumped["2-8-3-3"]["observation"] == "not_observed"




def _rec(cid: str, tier: EvidenceTier, status: ComplianceStatus) -> ControlAssessment:
    return ControlAssessment(control_id=cid, tier=tier, status=status)


def test_withholding_evidence_never_scores_better_than_failing_evidence() -> None:
    universe = frozenset({"a-1", "a-2", "a-3", "a-4"})
    passing = [_rec("a-1", EvidenceTier.TIER_2, ComplianceStatus.COMPLIANT)]
    failing = _rec("a-2", EvidenceTier.TIER_2, ComplianceStatus.NON_COMPLIANT)
    disclosed = compute_dual_score([*passing, failing], universe=universe)
    withheld = compute_dual_score(passing, universe=universe)
    assert withheld.documented_score == disclosed.documented_score == 0.25
    assert withheld.evidence_coverage == 0.25
    assert disclosed.evidence_coverage == 0.5


def test_without_a_universe_the_documented_score_is_over_evidenced_controls() -> None:
    score = compute_dual_score([_rec("a-1", EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT)])
    assert score.documented_score == 1.0
    assert score.evidence_coverage == 1.0


def test_records_outside_the_universe_are_ignored() -> None:
    universe = frozenset({"a-1"})
    alone = compute_dual_score([], universe=universe)
    with_parent = compute_dual_score(
        [_rec("x-9", EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT)], universe=universe
    )
    failing = compute_dual_score(
        [_rec("x-9", EvidenceTier.TIER_2, ComplianceStatus.NON_COMPLIANT)], universe=universe
    )
    assert alone.documented_score == with_parent.documented_score == failing.documented_score == 0.0
    assert with_parent.documented_total_weight == 1.0


def test_a_universe_with_non_uniform_weights_is_refused() -> None:
    weighted = ControlAssessment(
        control_id="a-1", tier=EvidenceTier.TIER_2, status=ComplianceStatus.COMPLIANT, weight=0.4
    )
    with pytest.raises(ValueError, match="uniform"):
        compute_dual_score([weighted], universe=frozenset({"a-1", "a-2"}))


def test_evidence_coverage_counts_assessed_records_only() -> None:
    universe = frozenset({"a-1", "a-2"})
    unread = _rec("a-1", EvidenceTier.TIER_1, ComplianceStatus.NOT_ASSESSED)
    assert compute_dual_score([unread], universe=universe).evidence_coverage == 0.0


def test_a_claim_above_an_unobserved_control_does_not_pass() -> None:
    claim = _rec("2-8-3", EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT)
    merged = merge_assessments(tier1_assessments([], unobserved=frozenset({"2-8-3-3"})), [claim])
    parent = next(a for a in merged if a.control_id == "2-8-3")
    assert parent.status is ComplianceStatus.NOT_ASSESSED


def test_unobserved_must_be_stated() -> None:
    with pytest.raises(TypeError):
        tier1_assessments([])


def test_assessments_round_trip_through_their_serialised_form() -> None:
    for a in tier1_assessments([], unobserved=frozenset({"2-8-3-3"})):
        assert ControlAssessment.model_validate(a.model_dump()) == a



_IDS = ["2-8-2", "2-8-3", "2-8-3-3", "2-4-3-5", "2-15-3-1", "1-3-2", "1-3-2-1", "3-1-1"]
_UNIVERSE = frozenset({"2-8-2", "2-8-3-3", "2-4-3-5", "2-15-3-1", "1-3-2", "1-3-2-1", "3-1-1"})
_records = st.lists(
    st.builds(
        _rec,
        st.sampled_from(_IDS),
        st.sampled_from([EvidenceTier.TIER_2, EvidenceTier.TIER_3]),
        st.sampled_from([ComplianceStatus.COMPLIANT, ComplianceStatus.NON_COMPLIANT]),
    ),
    max_size=8,
    unique_by=lambda r: r.control_id,
)
_checkable = frozenset({"2-8-3-3", "2-4-3-5", "2-15-3-1"})


def _score(unobserved: frozenset[str], records: list[ControlAssessment]):
    t1 = tier1_assessments([], checkable=_checkable, unobserved=unobserved)
    return compute_dual_score(merge_assessments(t1, records), universe=_UNIVERSE)


@settings(max_examples=300, deadline=None)
@given(
    records=_records,
    more=st.sets(st.sampled_from(sorted(_checkable))),
    base=st.sets(st.sampled_from(sorted(_checkable))),
)
def test_reading_less_never_raises_either_score(records, more, base) -> None:
    before = _score(frozenset(base), records)
    after = _score(frozenset(base | more), records)
    assert after.assessed_score <= before.assessed_score + 1e-12
    assert after.documented_score <= before.documented_score + 1e-12


@settings(max_examples=300, deadline=None)
@given(
    records=_records,
    drop=st.integers(min_value=0, max_value=7),
    unobserved=st.sets(st.sampled_from(sorted(_checkable))),
)
def test_withholding_any_record_never_raises_the_documented_score(records, drop, unobserved) -> None:
    if not records:
        return
    kept = [r for i, r in enumerate(records) if i != drop % len(records)]
    full = _score(frozenset(unobserved), records)
    withheld = _score(frozenset(unobserved), kept)
    assert withheld.documented_score <= full.documented_score + 1e-12
