from __future__ import annotations

import numpy as np
import pytest

from p2c.scoring.weights import (
    CR_THRESHOLD,
    InconsistentComparisons,
    ahp_weights,
    ahp_weights_checked,
    bwm_weights,
    weight_agreement,
)


def test_consistent_matrix_has_zero_cr_and_known_weights() -> None:
    result = ahp_weights([[1, 2, 4], [0.5, 1, 2], [0.25, 0.5, 1]])
    assert result.consistency_ratio == pytest.approx(0.0, abs=1e-9)
    assert result.lambda_max == pytest.approx(3.0, abs=1e-9)
    assert result.weights == pytest.approx([4 / 7, 2 / 7, 1 / 7], abs=1e-9)
    assert result.consistent


def test_saaty_reference_cr_matches_published_value() -> None:
    result = ahp_weights([[1, 3, 5], [1 / 3, 1, 3], [1 / 5, 1 / 3, 1]])
    assert result.consistency_index == pytest.approx(0.0193, abs=5e-4)
    assert result.consistency_ratio == pytest.approx(0.0332, abs=1e-3)
    assert result.consistent


def test_lambda_max_agrees_with_independent_computation() -> None:
    matrix = np.array([[1, 3, 5], [1 / 3, 1, 3], [1 / 5, 1 / 3, 1]])
    result = ahp_weights(matrix.tolist())
    w = np.array(result.weights)
    lam_independent = float(np.mean((matrix @ w) / w))
    assert result.lambda_max == pytest.approx(lam_independent, abs=1e-9)


def test_weights_sum_to_one_and_are_positive() -> None:
    result = ahp_weights([[1, 3, 5], [1 / 3, 1, 3], [1 / 5, 1 / 3, 1]])
    assert sum(result.weights) == pytest.approx(1.0, abs=1e-12)
    assert all(w > 0 for w in result.weights)


def test_inconsistent_matrix_is_rejected() -> None:
    cyclic = [[1, 9, 1 / 9], [1 / 9, 1, 9], [9, 1 / 9, 1]]
    result = ahp_weights(cyclic)
    assert result.consistency_ratio > CR_THRESHOLD
    assert not result.consistent
    with pytest.raises(InconsistentComparisons):
        ahp_weights_checked(cyclic)


def test_checked_passes_a_consistent_matrix() -> None:
    result = ahp_weights_checked([[1, 2], [0.5, 1]])
    assert result.consistent


def test_non_reciprocal_and_non_square_are_errors() -> None:
    with pytest.raises(ValueError, match="reciprocal"):
        ahp_weights([[1, 3], [1, 1]])
    with pytest.raises(ValueError, match="square"):
        ahp_weights([[1, 2, 3], [0.5, 1, 2]])
    with pytest.raises(ValueError, match="positive"):
        ahp_weights([[1, 0], [0, 1]])


def test_bwm_consistent_input_has_zero_xi_and_recovers_weights() -> None:
    w_true = [0.5, 0.3, 0.2]
    a_best = [w_true[0] / w_true[j] for j in range(3)]
    a_worst = [w_true[j] / w_true[2] for j in range(3)]
    result = bwm_weights(a_best, a_worst, best_index=0, worst_index=2)
    assert result.xi == pytest.approx(0.0, abs=1e-6)
    assert result.consistency_ratio == pytest.approx(0.0, abs=1e-6)
    assert result.weights == pytest.approx(w_true, abs=1e-4)
    assert result.consistent


def test_bwm_agrees_with_ahp_on_consistent_data() -> None:
    w_true = [0.5, 0.3, 0.2]
    a_best = [w_true[0] / w_true[j] for j in range(3)]
    a_worst = [w_true[j] / w_true[2] for j in range(3)]
    bwm = bwm_weights(a_best, a_worst, best_index=0, worst_index=2)
    ahp = ahp_weights([[w_true[i] / w_true[j] for j in range(3)] for i in range(3)])
    assert weight_agreement(bwm.weights, ahp.weights) < 1e-3


def test_bwm_inconsistent_input_is_rejected() -> None:
    result = bwm_weights([1, 3, 2], [2, 3, 1], best_index=0, worst_index=2)
    assert result.xi > 0
    assert result.consistency_ratio > CR_THRESHOLD
    assert not result.consistent


def test_bwm_large_abw_inconsistency_is_rejected() -> None:
    result = bwm_weights([1, 8, 9], [9, 8, 1], best_index=0, worst_index=2)
    assert result.consistency_ratio > CR_THRESHOLD
    assert not result.consistent


def test_bwm_validates_inputs() -> None:
    with pytest.raises(ValueError, match="equal length"):
        bwm_weights([1, 2, 3], [1, 2], best_index=0, worst_index=1)
    with pytest.raises(ValueError, match="out of range"):
        bwm_weights([1, 2], [2, 1], best_index=0, worst_index=5)


def test_bwm_rejects_best_equal_worst() -> None:
    with pytest.raises(ValueError, match="must differ"):
        bwm_weights([1, 5, 1], [1, 5, 1], best_index=0, worst_index=0)


def test_bwm_rejects_nonunit_self_preference() -> None:
    with pytest.raises(ValueError, match="must be 1"):
        bwm_weights([3, 2, 1], [3, 2, 1], best_index=0, worst_index=2)


def test_bwm_ci_zero_with_positive_xi_is_not_consistent() -> None:
    result = bwm_weights([1, 2, 1.2], [1.2, 1.1, 1], best_index=0, worst_index=2)
    if result.xi > 1e-9:
        assert result.consistency_ratio == float("inf")
        assert not result.consistent


def test_ahp_weights_match_independent_power_iteration() -> None:
    matrix = np.array([[1, 3, 5, 2], [1 / 3, 1, 3, 1 / 2], [1 / 5, 1 / 3, 1, 1 / 4], [1 / 2, 2, 4, 1]])
    result = ahp_weights(matrix.tolist())
    v = np.ones(matrix.shape[0]) / matrix.shape[0]
    for _ in range(2000):
        v = matrix @ v
        v = v / v.sum()
    assert np.allclose(result.weights, v, atol=1e-6)


def test_consistent_matrix_cr_is_never_negative() -> None:
    result = ahp_weights([[1, 2, 4], [0.5, 1, 2], [0.25, 0.5, 1]])
    assert result.consistency_ratio >= 0.0
