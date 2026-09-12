from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from scipy.optimize import linprog

CR_THRESHOLD = 0.10

SAATY_RI: dict[int, float] = {
    1: 0.0,
    2: 0.0,
    3: 0.58,
    4: 0.90,
    5: 1.12,
    6: 1.24,
    7: 1.32,
    8: 1.41,
    9: 1.45,
    10: 1.49,
    11: 1.51,
    12: 1.48,
    13: 1.56,
    14: 1.57,
    15: 1.59,
}

BWM_CI: dict[int, float] = {
    1: 0.0,
    2: 0.44,
    3: 1.0,
    4: 1.63,
    5: 2.30,
    6: 3.0,
    7: 3.73,
    8: 4.47,
    9: 5.23,
}

_RECIPROCAL_ATOL = 1e-9
_UNIT_TOL = 1e-9


class InconsistentComparisons(ValueError):
    pass


@dataclass(frozen=True)
class AHPResult:

    weights: tuple[float, ...]
    lambda_max: float
    consistency_index: float
    consistency_ratio: float
    order: int

    @property
    def consistent(self) -> bool:
        return self.consistency_ratio <= CR_THRESHOLD


@dataclass(frozen=True)
class BWMResult:
    weights: tuple[float, ...]
    xi: float
    consistency_ratio: float
    lp_xi: float = 0.0

    @property
    def consistent(self) -> bool:
        return self.consistency_ratio <= CR_THRESHOLD


_NDIM_2D = 2


def _validate_reciprocal(matrix: np.ndarray) -> None:
    if matrix.ndim != _NDIM_2D or matrix.shape[0] != matrix.shape[1]:
        raise ValueError("pairwise matrix must be square")
    if matrix.shape[0] < 1:
        raise ValueError("pairwise matrix must be non-empty")
    if np.any(matrix <= 0):
        raise ValueError("pairwise entries must be positive")
    n = matrix.shape[0]
    if not np.allclose(np.diagonal(matrix), 1.0, atol=_RECIPROCAL_ATOL):
        raise ValueError("pairwise diagonal must be 1")
    if not np.allclose(matrix * matrix.T, np.ones((n, n)), atol=1e-6):
        raise ValueError("pairwise matrix must be reciprocal (a_ij * a_ji == 1)")


def ahp_weights(matrix: Sequence[Sequence[float]]) -> AHPResult:
    a = np.asarray(matrix, dtype=float)
    _validate_reciprocal(a)
    n = a.shape[0]
    if n == 1:
        return AHPResult((1.0,), 1.0, 0.0, 0.0, 1)

    eigenvalues, eigenvectors = np.linalg.eig(a)
    principal = int(np.argmax(eigenvalues.real))
    lambda_max = float(eigenvalues[principal].real)
    vector = np.abs(eigenvectors[:, principal].real)
    weights = vector / vector.sum()

    consistency_index = (lambda_max - n) / (n - 1)
    random_index = SAATY_RI.get(n)
    if random_index is None:
        raise ValueError(f"no Saaty RI for order {n} (max {max(SAATY_RI)})")
    consistency_ratio = 0.0 if random_index == 0 else max(0.0, consistency_index / random_index)
    return AHPResult(
        weights=tuple(float(w) for w in weights),
        lambda_max=lambda_max,
        consistency_index=consistency_index,
        consistency_ratio=consistency_ratio,
        order=n,
    )


def ahp_weights_checked(matrix: Sequence[Sequence[float]]) -> AHPResult:
    result = ahp_weights(matrix)
    if not result.consistent:
        raise InconsistentComparisons(
            f"AHP consistency ratio {result.consistency_ratio:.4f} exceeds {CR_THRESHOLD}"
        )
    return result


def bwm_weights(
    best_to_others: Sequence[float],
    others_to_worst: Sequence[float],
    *,
    best_index: int,
    worst_index: int,
) -> BWMResult:
    a_b = np.asarray(best_to_others, dtype=float)
    a_w = np.asarray(others_to_worst, dtype=float)
    n = a_b.shape[0]
    if a_w.shape[0] != n:
        raise ValueError("best_to_others and others_to_worst must have equal length")
    if not (0 <= best_index < n and 0 <= worst_index < n):
        raise ValueError("best_index / worst_index out of range")
    if best_index == worst_index:
        raise ValueError("best_index and worst_index must differ")
    if np.any(a_b <= 0) or np.any(a_w <= 0):
        raise ValueError("comparison values must be positive")
    if abs(float(a_b[best_index]) - 1.0) > _UNIT_TOL or abs(float(a_w[worst_index]) - 1.0) > _UNIT_TOL:
        raise ValueError("best-to-best and worst-to-worst preferences must be 1")

    num_vars = n + 1
    xi_col = n
    cost = np.zeros(num_vars)
    cost[xi_col] = 1.0

    rows: list[list[float]] = []
    rhs: list[float] = []
    for j in range(n):
        for sign in (1.0, -1.0):
            row = np.zeros(num_vars)
            row[best_index] += sign
            row[j] -= sign * a_b[j]
            row[xi_col] = -1.0
            rows.append(list(row))
            rhs.append(0.0)
        for sign in (1.0, -1.0):
            row = np.zeros(num_vars)
            row[j] += sign
            row[worst_index] -= sign * a_w[j]
            row[xi_col] = -1.0
            rows.append(list(row))
            rhs.append(0.0)

    a_eq = [list(np.concatenate([np.ones(n), [0.0]]))]
    b_eq = [1.0]
    bounds = [(0.0, None)] * n + [(0.0, None)]

    result = linprog(cost, A_ub=rows, b_ub=rhs, A_eq=a_eq, b_eq=b_eq, bounds=bounds, method="highs")
    if not result.success:
        raise ValueError(f"BWM LP did not solve: {result.message}")

    weights = result.x[:n]
    weights = weights / weights.sum()
    lp_xi = float(result.x[xi_col])

    w_b, w_w = float(weights[best_index]), float(weights[worst_index])
    xi = 0.0
    for j in range(n):
        w_j = float(weights[j])
        if w_j > 0:
            xi = max(xi, abs(w_b / w_j - float(a_b[j])))
        if w_w > 0:
            xi = max(xi, abs(w_j / w_w - float(a_w[j])))

    a_bw = min(max(round(float(a_b[worst_index])), 1), max(BWM_CI))
    ci = BWM_CI[a_bw]
    consistency_ratio = (xi / ci) if ci != 0 else (0.0 if xi <= _UNIT_TOL else float("inf"))
    return BWMResult(
        weights=tuple(float(w) for w in weights),
        xi=xi,
        consistency_ratio=consistency_ratio,
        lp_xi=lp_xi,
    )


def weight_agreement(a: Sequence[float], b: Sequence[float]) -> float:
    va, vb = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    if va.shape != vb.shape:
        raise ValueError("weight vectors must have equal length")
    return float(np.max(np.abs(va - vb)))
