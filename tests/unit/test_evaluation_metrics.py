from __future__ import annotations

import math

import numpy as np
import pytest

from p2c.evaluation import metrics as M


def test_set_prf_textbook() -> None:
    prf = M.set_prf({"a", "b", "c"}, {"b", "c", "d"})
    assert prf.true_positive == 2 and prf.false_positive == 1 and prf.false_negative == 1
    assert prf.precision == pytest.approx(2 / 3)
    assert prf.recall == pytest.approx(2 / 3)
    assert prf.f1 == pytest.approx(2 / 3)


def test_prf_edges() -> None:
    assert M.set_prf(set(), set()).f1 == 0.0
    perfect = M.set_prf({"x"}, {"x"})
    assert perfect.precision == 1.0 and perfect.recall == 1.0 and perfect.f1 == 1.0


def test_micro_vs_macro_f1() -> None:
    pairs = [({"a"}, {"a"}), ({"b", "c"}, {"b", "d"})]
    assert M.micro_prf(pairs).f1 == pytest.approx(2 / 3)
    assert M.macro_f1(pairs) == pytest.approx(0.75)


def test_mcc_matches_the_hand_computed_value() -> None:
    assert M.mcc_from_counts(90, 10, 20, 80) == pytest.approx(7000 / math.sqrt(99_000_000))
    assert M.mcc_from_counts(5, 0, 0, 5) == pytest.approx(1.0)
    assert M.mcc_from_counts(0, 5, 5, 0) == pytest.approx(-1.0)


def test_whole_table_measures_pin_the_predict_all_floor() -> None:
    assert M.prf_from_counts(900, 700, 0).f1 == pytest.approx(0.72)
    assert M.mcc_from_counts(900, 700, 0, 0) == 0.0
    assert M.balanced_accuracy_from_counts(900, 700, 0, 0) == pytest.approx(0.5)


def test_balanced_accuracy_averages_sensitivity_and_specificity() -> None:
    assert M.balanced_accuracy_from_counts(90, 10, 20, 80) == pytest.approx((90 / 110 + 80 / 90) / 2)


def test_fuzzy_credits_parent_child_nearmiss() -> None:
    assert M.set_prf({"2-5-3"}, {"2-5-3-1"}).true_positive == 0
    fz = M.fuzzy_set_prf({"2-5-3"}, {"2-5-3-1"}, threshold=0.7)
    assert fz.true_positive == 1 and fz.false_positive == 0 and fz.false_negative == 0


def test_fuzzy_is_one_to_one() -> None:
    fz = M.fuzzy_set_prf({"2-5-3"}, {"2-5-3-1", "2-5-3-2"}, threshold=0.7)
    assert fz.true_positive == 1 and fz.false_negative == 1


def test_control_id_similarity_unrelated_is_low() -> None:
    assert M.control_id_similarity("2-5-3-1", "2-5-3-1") == 1.0
    assert M.control_id_similarity("1-1-1", "4-9-9-9") < 0.7


def test_control_id_similarity_only_credits_true_family_relation() -> None:
    assert M.control_id_similarity("2-15-3-1", "2-15-3-3") == 0.8
    assert M.control_id_similarity("2-5-3", "2-5-3-1") == 0.85
    assert M.control_id_similarity("2-8-3-3", "2-15-3-3") == 0.0
    assert M.control_id_similarity("2-5-3-1", "2-5-4-1") == 0.0


def test_fuzzy_optimal_matching_credits_all_near_misses() -> None:
    fz = M.fuzzy_set_prf({"2-5-3-1", "2-5-3-2"}, {"2-5-3", "2-5-3-9"}, threshold=0.7)
    assert fz.true_positive == 2
    assert M.fuzzy_set_prf({"2-5-3"}, {"2-5-3-1", "2-5-3-2"}, threshold=0.7).true_positive == 1


def test_cohens_kappa_classic_040() -> None:
    a = ["y"] * 25 + ["n"] * 25
    b = ["y"] * 20 + ["n"] * 5 + ["y"] * 10 + ["n"] * 15
    assert M.cohens_kappa(a, b) == pytest.approx(0.40, abs=1e-9)


def test_cohens_kappa_perfect_and_constant() -> None:
    assert M.cohens_kappa(["a", "b", "c"], ["a", "b", "c"]) == 1.0
    assert M.cohens_kappa(["a", "a"], ["a", "a"]) == 1.0


def test_cohens_kappa_length_mismatch_raises() -> None:
    with pytest.raises(ValueError, match="same number"):
        M.cohens_kappa(["a"], ["a", "b"])


def test_krippendorff_nominal_hand_computed() -> None:
    alpha = M.krippendorff_alpha([[1, 1, 2, 2], [1, 2, 2, 2]], level="nominal")
    assert alpha == pytest.approx(8 / 15, abs=1e-9)


def test_krippendorff_perfect_and_missing() -> None:
    assert M.krippendorff_alpha([[1, 2, 3], [1, 2, 3]], level="nominal") == 1.0
    assert M.krippendorff_alpha([[1, 2, 3], [1, 2, 3]], level="ordinal") == 1.0
    data: list[list[object]] = [[1, 2, M.MISSING], [1, 2, 3]]
    assert M.krippendorff_alpha(data, level="nominal") == 1.0


def test_krippendorff_ordinal_beats_nominal_on_near_misses() -> None:
    data: list[list[object]] = [[1, 2, 3, 4, 5], [1, 2, 3, 4, 4]]
    nominal = M.krippendorff_alpha(data, level="nominal")
    ordinal = M.krippendorff_alpha(data, level="ordinal")
    assert ordinal > nominal


def test_krippendorff_bad_level_raises() -> None:
    with pytest.raises(ValueError, match=r"nominal.*ordinal"):
        M.krippendorff_alpha([[1, 2], [1, 2]], level="interval")


def test_sus_anchors() -> None:
    assert M.sus_score([3] * 10) == 50.0
    assert M.sus_score([5, 1, 5, 1, 5, 1, 5, 1, 5, 1]) == 100.0
    assert M.sus_score([1, 5, 1, 5, 1, 5, 1, 5, 1, 5]) == 0.0


def test_sus_validation() -> None:
    with pytest.raises(ValueError, match="10 items"):
        M.sus_score([3] * 9)
    with pytest.raises(ValueError, match="must be 1"):
        M.sus_score([6] + [3] * 9)


def test_latency_speedup() -> None:
    cmp = M.latency_speedup(atlas_seconds=30.0, baseline_seconds=3600.0)
    assert cmp.speedup == pytest.approx(120.0)
    with pytest.raises(ValueError, match="positive"):
        M.latency_speedup(0.0, 1.0)


def test_bootstrap_is_deterministic_and_brackets_point() -> None:
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    a = M.bootstrap_ci(values, seed=42, n_boot=2000)
    b = M.bootstrap_ci(values, seed=42, n_boot=2000)
    assert (a.point, a.ci_low, a.ci_high) == (b.point, b.ci_low, b.ci_high)
    assert a.point == pytest.approx(3.0)
    assert a.ci_low <= a.point <= a.ci_high


def test_bootstrap_single_value_is_degenerate() -> None:
    e = M.bootstrap_ci([7.0])
    assert e.point == e.ci_low == e.ci_high == 7.0


def test_cohens_d_reference() -> None:
    assert M.cohens_d([1, 2, 3, 4], [1, 2, 3, 4]) == 0.0
    assert M.cohens_d([10, 11, 12, 13], [1, 2, 3, 4]) > 2.0


def test_bootstrap_custom_statistic() -> None:
    est = M.bootstrap_ci([1, 2, 3, 4, 100], statistic=lambda x: float(np.median(x)), seed=1)
    assert est.point == 3.0


def test_case_f1_true_negative_convention() -> None:
    assert M.case_f1(set(), set()) == 1.0
    assert M.set_prf(set(), set()).f1 == 0.0
    assert M.case_f1({"a"}, {"a", "b"}) == pytest.approx(2 / 3)
    assert M.case_f1({"a", "b", "c"}, {"a"}) == pytest.approx(0.5)
    assert M.macro_f1([(set(), set()), ({"a", "b", "c"}, {"a"})]) == pytest.approx(0.75)


def test_wilson_interval_matches_reference() -> None:
    ci = M.wilson_interval(10, 10)
    assert ci.point == 1.0
    assert ci.ci_low == pytest.approx(0.7225, abs=1e-3)
    assert ci.ci_high == 1.0
    mid = M.wilson_interval(5, 10)
    assert mid.ci_low < 0.5 < mid.ci_high
    assert mid.ci_low >= 0.0 and mid.ci_high <= 1.0
    for bad in ((0, 0), (5, 3), (-1, 10)):
        with pytest.raises(ValueError):
            M.wilson_interval(*bad)


def test_masi_distance_matches_the_published_definition() -> None:
    s = frozenset
    assert M.masi_distance(s({"x"}), s({"x"})) == 0.0
    assert M.masi_distance(s({"x"}), s({"x", "y"})) == pytest.approx(1 - (1 / 2) * (2 / 3))
    assert M.masi_distance(s({"x", "y"}), s({"y", "z"})) == pytest.approx(1 - (1 / 3) * (1 / 3))
    assert M.masi_distance(s({"a", "b"}), s({"a", "b", "c"})) == pytest.approx(1 - (2 / 3) * (2 / 3))
    assert M.masi_distance(s({"x"}), s({"y"})) == 1.0


def test_masi_distance_is_symmetric() -> None:
    s = frozenset
    pairs = [(s({"x"}), s({"x", "y"})), (s({"a", "b"}), s({"b", "c"})), (s({"p"}), s({"q"}))]
    for a, b in pairs:
        assert M.masi_distance(a, b) == M.masi_distance(b, a)


def test_krippendorff_alpha_sets_anchors() -> None:
    s = frozenset
    perfect = [[s({"x"}), s({"y"}), s({"z"})]] * 3
    assert M.krippendorff_alpha_sets(perfect) == 1.0
    disagree = [[s({f"c{u}{r}"}) for u in range(6)] for r in range(3)]
    assert M.krippendorff_alpha_sets(disagree) <= 0.0


def test_masi_alpha_credits_overlap_where_strict_identity_does_not() -> None:
    s = frozenset
    matrix: list[list[frozenset[str] | None]] = [
        [s({"x"}), s({"p"})],
        [s({"x", "y"}), s({"q"})],
    ]
    strict = M.krippendorff_alpha_sets(matrix, distance=lambda a, b: 0.0 if a == b else 1.0)
    assert M.krippendorff_alpha_sets(matrix) > strict
