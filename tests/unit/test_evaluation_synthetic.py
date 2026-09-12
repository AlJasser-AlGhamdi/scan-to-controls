from __future__ import annotations

import json

import pytest

from p2c.evaluation.synthetic import (
    _APEX_ONLY_CHECKS,
    _FALSE_ALARM_CHECKS,
    _HOST_FETCHED_CHECKS,
    CATEGORIES,
    CONDITION_FACTOR_EDGE,
    CONDITION_FACTOR_ORIGIN,
    FALSE_ALARM,
    OFF_SURFACE_COVERAGE,
    SCAN_CONDITIONS,
    SECTORS,
    SENSITIVITY,
    SIZE_BANDS,
    EvalCase,
    expert_key,
    generate_cases,
    off_surface_pools,
)
from p2c.mapping.rules import check_id_from_finding
from p2c.scanning.catalog import CheckId
from p2c.scoring.assemble import TIER1_CHECKABLE
from p2c.scoring.contradictions import control_related


def test_generate_is_deterministic() -> None:
    a = generate_cases(50)
    b = generate_cases(50)
    assert len(a) == 50
    assert [c.case_id for c in a] == [c.case_id for c in b]
    assert [c.profile.apex for c in a] == [c.profile.apex for c in b]
    assert [sorted(c.ground_truth.control_ids) for c in a] == [sorted(c.ground_truth.control_ids) for c in b]


def test_seed_changes_the_corpus() -> None:
    a = generate_cases(20, seed=1)
    b = generate_cases(20, seed=2)
    assert [c.profile.apex for c in a] != [c.profile.apex for c in b]


def test_no_empty_profiles_and_all_sectors_reachable() -> None:
    cases = generate_cases(50)
    assert all(c.injected for c in cases)
    assert all(c.ground_truth.control_ids for c in cases)
    assert len({c.sector for c in cases}) >= 4
    assert {c.sector for c in cases} <= {s.name for s in SECTORS}


def test_size_bands_are_drawn_and_condition_the_estate() -> None:
    cases = generate_cases(100)
    bands = {c.size_band for c in cases}
    assert bands <= {b.name for b in SIZE_BANDS}
    assert bands == {"small", "medium"}
    n_small = sum(c.size_band == "small" for c in cases)
    assert n_small > sum(c.size_band == "medium" for c in cases)
    for c in cases:
        n_hosts = len(c.profile.assets)
        if c.size_band == "small":
            assert 2 <= n_hosts <= 5, (c.case_id, n_hosts)
        else:
            assert 4 <= n_hosts <= 9, (c.case_id, n_hosts)


def test_ground_truth_never_leaks_into_pipeline_input() -> None:
    for case in generate_cases(50):
        visible = json.dumps(case.pipeline_input().model_dump(mode="json"))
        assert not any(cid in visible for cid in case.ground_truth.control_ids)
        for finding in case.findings():
            assert finding.control_ids == []
            dumped = json.dumps(finding.model_dump(mode="json"), default=str)
            assert not any(cid in dumped for cid in case.ground_truth.control_ids)


def test_profiles_span_postures_and_include_overstatements() -> None:
    cases = generate_cases(50)
    assert {c.posture for c in cases} <= {"strong", "moderate", "weak"}
    assert len({c.posture for c in cases}) >= 2
    overstated = sum(len({a.control_id for a in c.attestations} & c.ground_truth.control_ids) for c in cases)
    assert overstated > 0


def test_observed_state_differs_from_truth() -> None:
    cases = generate_cases(50)
    missed = false_alarm = 0
    for c in cases:
        true = {(i.asset, i.check) for i in c.true_injected}
        observed = {(i.asset, i.check) for i in c.injected}
        missed += len(true - observed)
        false_alarm += len(observed - true)
    assert missed > 0, "detection model never misses a truly-present issue"
    assert false_alarm > 0, "detection model never raises a false alarm"


def test_findings_recover_their_check_id() -> None:
    case = generate_cases(5)[0]
    for finding, inj in zip(case.findings(), case.injected, strict=True):
        assert check_id_from_finding(finding) == inj.check


def test_expert_key_covers_all_checks_and_is_catalog_valid() -> None:
    key = expert_key()
    all_checks = {c for checks in CATEGORIES.values() for c in checks}
    assert set(key) == all_checks
    assert all(ids for ids in key.values())


def test_generate_rejects_nonpositive_n() -> None:
    with pytest.raises(ValueError, match="positive"):
        generate_cases(0)


def test_case_is_frozen_dataclass() -> None:
    case = generate_cases(1)[0]
    assert isinstance(case, EvalCase)
    with pytest.raises(AttributeError):
        case.sector = "hacked"


def test_false_alarm_model_has_no_dead_entries() -> None:
    nonzero = {c for c, v in FALSE_ALARM.items() if v > 0.0}
    assert set(_FALSE_ALARM_CHECKS) == nonzero
    assert len(_FALSE_ALARM_CHECKS) == len(set(_FALSE_ALARM_CHECKS))
    assert FALSE_ALARM[CheckId.MISSING_HSTS] == 0.0
    assert FALSE_ALARM[CheckId.SPF_MISSING] == 0.0
    all_checks = {c for checks in CATEGORIES.values() for c in checks}
    assert set(SENSITIVITY) == all_checks and set(FALSE_ALARM) == all_checks


def test_scan_conditions_are_drawn_and_deterministic() -> None:
    cases = generate_cases(50)
    for c in cases:
        assert set(c.scan_conditions.values()) <= set(SCAN_CONDITIONS)
        assert len(c.scan_conditions) == len(c.profile.assets)
        assert 0.97 <= c.scanner_competence <= 1.0
    again = generate_cases(50)
    assert [c.scan_conditions for c in cases] == [c.scan_conditions for c in again]
    assert [c.scanner_competence for c in cases] == [c.scanner_competence for c in again]
    assert CONDITION_FACTOR_ORIGIN["cdn_fronted"] < CONDITION_FACTOR_EDGE["cdn_fronted"]
    assert CONDITION_FACTOR_ORIGIN["reachable"] == CONDITION_FACTOR_EDGE["reachable"] == 1.0


def test_obstruction_reduces_detection_but_dns_signals_are_exempt() -> None:
    assert _HOST_FETCHED_CHECKS.isdisjoint(_APEX_ONLY_CHECKS)
    cases = generate_cases(80)
    obstructed = sum(1 for c in cases for cond in c.scan_conditions.values() if cond != "reachable")
    assert obstructed > 0


def test_forced_fallbacks_never_fire_on_the_reported_corpus() -> None:
    cases = generate_cases(100)
    assert sum(c.forced_true_fallback for c in cases) == 0
    assert sum(c.forced_observe_fallback for c in cases) == 0


def test_off_surface_pools_come_from_the_overlay_and_are_unreachable_by_a_scan() -> None:
    internal, declarable = off_surface_pools()
    assert (len(internal), len(declarable)) == (72, 108)
    assert not set(internal) & set(declarable)
    for cid in (*internal, *declarable):
        assert not any(control_related(cid, checkable) for checkable in TIER1_CHECKABLE)
    assert list(internal) == sorted(internal) and list(declarable) == sorted(declarable)


def test_off_surface_evidence_is_present_schema_valid_and_deterministic() -> None:
    cases = generate_cases(50)
    internal_pool, declaration_pool = set(off_surface_pools()[0]), set(off_surface_pools()[1])
    assert any(c.internal_evidence for c in cases)
    for case in cases:
        for record in case.internal_evidence:
            assert record.control_id in internal_pool
            assert isinstance(record.compliant, bool)
        ids = [r.control_id for r in case.internal_evidence]
        assert len(ids) == len(set(ids))
        off_surface = [a for a in case.attestations if a.control_id not in TIER1_CHECKABLE]
        assert all(a.control_id in declaration_pool for a in off_surface)
    again = generate_cases(50)
    assert [c.internal_evidence for c in cases] == [c.internal_evidence for c in again]
    assert [[a.control_id for a in c.attestations] for c in cases] == [
        [a.control_id for a in c.attestations] for c in again
    ]
    readings = {r.compliant for c in cases for r in c.internal_evidence}
    assert readings == {True, False}


def test_off_surface_coverage_rises_with_posture() -> None:
    assert OFF_SURFACE_COVERAGE["strong"] > OFF_SURFACE_COVERAGE["moderate"] > OFF_SURFACE_COVERAGE["weak"]
    per_posture: dict[str, list[int]] = {"strong": [], "moderate": [], "weak": []}
    for case in generate_cases(100):
        off = len(case.internal_evidence) + sum(
            1 for a in case.attestations if a.control_id not in TIER1_CHECKABLE
        )
        per_posture[case.posture].append(off)
    means = {p: sum(v) / len(v) for p, v in per_posture.items() if v}
    assert means["strong"] > means["moderate"] > means["weak"]


def test_off_surface_evidence_is_drawn_last_and_moves_no_earlier_draw(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fingerprint(case: EvalCase) -> tuple[object, ...]:
        return (
            case.case_id,
            case.sector,
            case.size_band,
            case.posture,
            case.profile.apex,
            tuple(a.value for a in case.profile.assets),
            tuple(sorted(case.scan_conditions.items())),
            case.scanner_competence,
            case.true_injected,
            case.injected,
            tuple(sorted(case.ground_truth.control_ids)),
            tuple(
                (a.attestation_id, a.valid_from, a.valid_until)
                for a in case.attestations
                if a.control_id in TIER1_CHECKABLE
            ),
        )

    before = [fingerprint(c) for c in generate_cases(40)]
    off_before = [c.internal_evidence for c in generate_cases(40)]
    for posture, share in (("strong", 0.5), ("moderate", 0.4), ("weak", 0.3)):
        monkeypatch.setitem(OFF_SURFACE_COVERAGE, posture, share)
    after_cases = generate_cases(40)
    assert [fingerprint(c) for c in after_cases] == before
    assert [c.internal_evidence for c in after_cases] != off_before
