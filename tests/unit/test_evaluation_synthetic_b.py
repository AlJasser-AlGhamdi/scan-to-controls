from __future__ import annotations

import json

import pytest

from p2c.evaluation.synthetic import (
    _APEX_ONLY_CHECKS,
    CATEGORIES,
    expert_key,
    off_surface_pools,
)
from p2c.evaluation.synthetic import (
    _SUBDOMAIN_POOLS as COHORT_A_POOLS,
)
from p2c.evaluation.synthetic_b import (
    BASE_PREVALENCE,
    SECTORS_B,
    EvalCase,
    generate_cases_b,
)
from p2c.mapping.rules import check_id_from_finding
from p2c.scanning.catalog import CheckId
from p2c.scoring.assemble import TIER1_CHECKABLE
from p2c.scoring.contradictions import control_related


def test_generate_b_is_deterministic() -> None:
    a = generate_cases_b(50)
    b = generate_cases_b(50)
    assert len(a) == 50
    assert [c.case_id for c in a] == [c.case_id for c in b]
    assert [c.profile.apex for c in a] == [c.profile.apex for c in b]
    assert [sorted(c.ground_truth.control_ids) for c in a] == [sorted(c.ground_truth.control_ids) for c in b]


def test_seed_changes_the_b_corpus() -> None:
    a = generate_cases_b(20, seed=1)
    b = generate_cases_b(20, seed=2)
    assert [c.profile.apex for c in a] != [c.profile.apex for c in b]


def test_b_does_not_alias_cohort_a_domains() -> None:
    from p2c.evaluation.synthetic import generate_cases

    apex_a = {c.profile.apex for c in generate_cases(100)}
    apex_b = {c.profile.apex for c in generate_cases_b(100)}
    assert apex_a.isdisjoint(apex_b)


def test_b_case_matches_the_shared_schema() -> None:
    case = generate_cases_b(1)[0]
    assert isinstance(case, EvalCase)
    assert case.case_id.startswith("evalb-")
    assert case.profile.apex == case.profile.assets[0].value
    for finding, inj in zip(case.findings(), case.injected, strict=True):
        assert check_id_from_finding(finding) == inj.check
    with pytest.raises(AttributeError):
        case.sector = "hacked"


def test_b_uses_a_different_subdomain_naming_convention() -> None:
    labels: set[str] = set()
    for c in generate_cases_b(100):
        for asset in c.profile.assets[1:]:
            labels.add(asset.value.split(".", 1)[0])
    assert any(label.startswith("svc") for label in labels), "cohort B did not emit indexed svc hostnames"
    cohort_a_labels = {label for pool in COHORT_A_POOLS.values() for label in pool}
    distinctive_a = cohort_a_labels - {"dev", "staging", "uat", "test", "sandbox"}
    assert labels.isdisjoint(distinctive_a), "cohort B leaked cohort A's semantic pool labels"
    assert all(label.startswith("svc") or label == "sandbox" for label in labels)


def test_b_posture_is_continuous_not_three_bands() -> None:
    cases = generate_cases_b(100)
    distinct_true_counts = {len(c.true_injected) for c in cases}
    assert len(distinct_true_counts) > 10
    assert {c.sector for c in cases} <= {s.name for s in SECTORS_B}
    assert len({c.sector for c in cases}) >= 3


def test_b_ground_truth_never_leaks_into_pipeline_input() -> None:
    for case in generate_cases_b(50):
        visible = json.dumps(case.pipeline_input().model_dump(mode="json"))
        assert not any(cid in visible for cid in case.ground_truth.control_ids)
        for finding in case.findings():
            assert finding.control_ids == []
            dumped = json.dumps(finding.model_dump(mode="json"), default=str)
            assert not any(cid in dumped for cid in case.ground_truth.control_ids)


def test_b_observed_state_differs_from_truth() -> None:
    missed = false_alarm = 0
    for c in generate_cases_b(50):
        true = {(i.asset, i.check) for i in c.true_injected}
        observed = {(i.asset, i.check) for i in c.injected}
        missed += len(true - observed)
        false_alarm += len(observed - true)
    assert missed > 0 and false_alarm > 0


def test_b_corpus_is_non_degenerate_and_exercises_every_control() -> None:
    cases = generate_cases_b(100)
    assert all(c.injected for c in cases)
    true = set().union(*(set(c.ground_truth.control_ids) for c in cases))
    assert len(true) == 16
    assert sum(c.forced_true_fallback for c in cases) <= 2
    assert sum(c.forced_observe_fallback for c in cases) == 0


def test_b_base_prevalence_covers_every_non_role_check() -> None:
    all_checks = {c for checks in CATEGORIES.values() for c in checks}
    role_checks = {CheckId.EXPOSED_LOGIN_PANEL, CheckId.EXPOSED_DEV_ENVIRONMENT}
    assert set(BASE_PREVALENCE) == all_checks - role_checks
    assert all(0.0 <= v <= 1.0 for v in BASE_PREVALENCE.values())


def test_b_shares_the_expert_key_and_apex_placement() -> None:
    key = expert_key()
    for c in generate_cases_b(50):
        for inj in c.true_injected:
            assert inj.check in key
            if inj.check in _APEX_ONLY_CHECKS:
                assert inj.asset == c.profile.apex


def test_generate_b_rejects_nonpositive_n() -> None:
    with pytest.raises(ValueError, match="positive"):
        generate_cases_b(0)


def test_b_carries_the_same_off_surface_evidence_stream() -> None:
    internal_pool, declaration_pool = off_surface_pools()
    cases = generate_cases_b(50)
    assert any(c.internal_evidence for c in cases)
    for case in cases:
        assert all(r.control_id in set(internal_pool) for r in case.internal_evidence)
        off_surface = [a for a in case.attestations if a.control_id not in TIER1_CHECKABLE]
        assert all(a.control_id in set(declaration_pool) for a in off_surface)
        for cid in {a.control_id for a in off_surface}:
            assert not any(control_related(cid, checkable) for checkable in TIER1_CHECKABLE)
    assert [c.internal_evidence for c in cases] == [c.internal_evidence for c in generate_cases_b(50)]
