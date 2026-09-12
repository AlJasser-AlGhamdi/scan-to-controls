from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from statistics import NormalDist

import numpy as np
from scipy.optimize import linear_sum_assignment

MISSING = None

_MIN_RATINGS_PER_UNIT = 2
_SUS_ITEMS = 10
_SUS_MIN, _SUS_MAX = 1, 5
_MIN_GROUP = 2
_SUBCONTROL_SEGMENTS = 4


def _as_float(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError("krippendorff ratings must be numeric (encode categories as ints)")
    return float(value)


@dataclass(frozen=True)
class PRF:

    precision: float
    recall: float
    f1: float
    true_positive: int
    false_positive: int
    false_negative: int


def _f1(precision: float, recall: float) -> float:
    return 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)


def prf_from_counts(tp: int, fp: int, fn: int) -> PRF:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return PRF(precision, recall, _f1(precision, recall), tp, fp, fn)


def set_prf(predicted: set[str], gold: set[str]) -> PRF:
    tp = len(predicted & gold)
    return prf_from_counts(tp, len(predicted - gold), len(gold - predicted))


def case_f1(predicted: set[str], gold: set[str]) -> float:
    if not predicted and not gold:
        return 1.0
    return set_prf(predicted, gold).f1


def micro_prf(pairs: Sequence[tuple[set[str], set[str]]]) -> PRF:
    tp = fp = fn = 0
    for predicted, gold in pairs:
        tp += len(predicted & gold)
        fp += len(predicted - gold)
        fn += len(gold - predicted)
    return prf_from_counts(tp, fp, fn)


def macro_f1(pairs: Sequence[tuple[set[str], set[str]]]) -> float:
    if not pairs:
        return 0.0
    return float(np.mean([case_f1(p, g) for p, g in pairs]))


def mcc_from_counts(tp: int, fp: int, fn: int, tn: int) -> float:
    den = math.sqrt(float((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)))
    return 0.0 if den == 0.0 else (tp * tn - fp * fn) / den


def balanced_accuracy_from_counts(tp: int, fp: int, fn: int, tn: int) -> float:
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    tnr = tn / (tn + fp) if (tn + fp) else 0.0
    return (tpr + tnr) / 2


def control_id_similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    pa, pb = a.split("-"), b.split("-")
    shorter, longer = (pa, pb) if len(pa) <= len(pb) else (pb, pa)
    if longer[: len(shorter)] == shorter:
        extra = len(longer) - len(shorter)
        return max(0.0, 1.0 - 0.15 * extra)
    if len(pa) == len(pb) >= _SUBCONTROL_SEGMENTS and pa[:-1] == pb[:-1]:
        return 0.8
    return 0.0


def fuzzy_set_prf(predicted: set[str], gold: set[str], *, threshold: float = 0.7) -> PRF:
    preds, golds = sorted(predicted), sorted(gold)
    if not preds or not golds:
        return prf_from_counts(0, len(preds), len(golds))
    sim = np.array([[control_id_similarity(p, g) for g in golds] for p in preds])
    eligible = sim >= threshold
    cost = np.where(eligible, -sim, sim.size + 1.0)
    rows, cols = linear_sum_assignment(cost)
    tp = int(sum(1 for r, c in zip(rows, cols, strict=True) if eligible[r, c]))
    return prf_from_counts(tp, len(preds) - tp, len(golds) - tp)


def cohens_kappa(rater_a: Sequence[object], rater_b: Sequence[object]) -> float:
    if len(rater_a) != len(rater_b):
        raise ValueError("raters must label the same number of items")
    n = len(rater_a)
    if n == 0:
        raise ValueError("need at least one item")
    categories = sorted({*rater_a, *rater_b}, key=repr)
    idx = {c: i for i, c in enumerate(categories)}
    k = len(categories)
    conf = np.zeros((k, k))
    for a, b in zip(rater_a, rater_b, strict=True):
        conf[idx[a], idx[b]] += 1
    conf /= n
    po = float(np.trace(conf))
    pe = float(np.sum(conf.sum(axis=0) * conf.sum(axis=1)))
    if pe == 1.0:
        return 1.0 if po == 1.0 else 0.0
    return (po - pe) / (1 - pe)


def _nominal_delta(c: float, k: float, _values: list[float]) -> float:
    return 0.0 if c == k else 1.0


def _ordinal_delta(c: float, k: float, values: list[float], marginals: dict[float, float]) -> float:
    lo, hi = (c, k) if c <= k else (k, c)
    between = sum(marginals[g] for g in values if lo <= g <= hi)
    return (between - (marginals[c] + marginals[k]) / 2.0) ** 2


def krippendorff_alpha(reliability: Sequence[Sequence[object]], *, level: str = "nominal") -> float:
    if level not in ("nominal", "ordinal"):
        raise ValueError("level must be 'nominal' or 'ordinal'")
    coders = [list(row) for row in reliability]
    if not coders:
        raise ValueError("need at least one coder")
    n_units = len(coders[0])
    if any(len(row) != n_units for row in coders):
        raise ValueError("every coder must rate the same number of units")

    values = sorted({_as_float(v) for row in coders for v in row if v is not MISSING})
    if len(values) <= 1:
        return 1.0
    vidx = {v: i for i, v in enumerate(values)}
    m = len(values)
    coincidence = np.zeros((m, m))
    for u in range(n_units):
        ratings = [_as_float(row[u]) for row in coders if row[u] is not MISSING]
        mu = len(ratings)
        if mu < _MIN_RATINGS_PER_UNIT:
            continue
        for i in range(mu):
            for j in range(mu):
                if i == j:
                    continue
                coincidence[vidx[ratings[i]], vidx[ratings[j]]] += 1.0 / (mu - 1)

    n_marginal = coincidence.sum(axis=1)
    n_total = float(n_marginal.sum())
    if n_total == 0:
        return 1.0
    marg = {v: float(n_marginal[vidx[v]]) for v in values}

    def delta2(ci: int, ki: int) -> float:
        c, k = values[ci], values[ki]
        if level == "nominal":
            return _nominal_delta(c, k, values)
        return _ordinal_delta(c, k, values, marg)

    observed = sum(float(coincidence[ci, ki]) * delta2(ci, ki) for ci in range(m) for ki in range(m))
    expected = sum(
        float(n_marginal[ci]) * float(n_marginal[ki]) * delta2(ci, ki) for ci in range(m) for ki in range(m)
    ) / (n_total - 1)
    if expected == 0:
        return 1.0
    return 1.0 - observed / expected


def masi_distance(a: frozenset[str], b: frozenset[str]) -> float:
    if a == b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    intersection = a & b
    if not intersection:
        return 1.0
    jaccard = len(intersection) / len(union)
    monotonicity = 2.0 / 3.0 if (a <= b or b <= a) else 1.0 / 3.0
    return 1.0 - jaccard * monotonicity


def krippendorff_alpha_sets(
    reliability: Sequence[Sequence[frozenset[str] | None]],
    *,
    distance: Callable[[frozenset[str], frozenset[str]], float] = masi_distance,
) -> float:
    coders = [list(row) for row in reliability]
    if len(coders) < _MIN_RATINGS_PER_UNIT:
        raise ValueError("need at least two coders")
    n_units = len(coders[0])
    if any(len(row) != n_units for row in coders):
        raise ValueError("every coder must rate the same number of units")

    per_unit: list[list[frozenset[str]]] = []
    pool: list[frozenset[str]] = []
    for u in range(n_units):
        rated = [row[u] for row in coders if row[u] is not MISSING]
        if len(rated) < _MIN_RATINGS_PER_UNIT:
            continue
        ratings = [r for r in rated if r is not None]
        per_unit.append(ratings)
        pool.extend(ratings)

    n = len(pool)
    if n < _MIN_RATINGS_PER_UNIT:
        return 1.0

    observed = 0.0
    for ratings in per_unit:
        mu = len(ratings)
        observed += math.fsum(
            distance(ratings[i], ratings[j]) for i in range(mu) for j in range(mu) if i != j
        ) / (mu - 1)
    observed /= n

    expected = math.fsum(distance(pool[i], pool[j]) for i in range(n) for j in range(n) if i != j)
    expected /= n * (n - 1)

    if expected == 0.0:
        return 1.0
    return 1.0 - observed / expected


def sus_score(responses: Sequence[int]) -> float:
    if len(responses) != _SUS_ITEMS:
        raise ValueError("SUS has exactly 10 items")
    if any(not (_SUS_MIN <= r <= _SUS_MAX) for r in responses):
        raise ValueError("SUS responses must be 1..5")
    total = 0
    for i, r in enumerate(responses):
        total += (r - 1) if i % 2 == 0 else (5 - r)
    return total * 2.5


def sus_mean(all_responses: Sequence[Sequence[int]]) -> float:
    if not all_responses:
        raise ValueError("need at least one SUS response")
    return float(np.mean([sus_score(r) for r in all_responses]))


@dataclass(frozen=True)
class LatencyComparison:
    atlas_seconds: float
    baseline_seconds: float
    speedup: float


def latency_speedup(atlas_seconds: float, baseline_seconds: float) -> LatencyComparison:
    if atlas_seconds <= 0 or baseline_seconds <= 0:
        raise ValueError("latencies must be positive")
    return LatencyComparison(atlas_seconds, baseline_seconds, baseline_seconds / atlas_seconds)


@dataclass(frozen=True)
class Estimate:
    point: float
    ci_low: float
    ci_high: float
    level: float = 0.95


def bootstrap_ci(
    values: Sequence[float],
    *,
    statistic: Callable[[np.ndarray], float] = lambda x: float(np.mean(x)),
    n_boot: int = 10_000,
    level: float = 0.95,
    seed: int = 0,
) -> Estimate:
    arr = np.asarray(values, dtype=float)
    if arr.size == 0:
        raise ValueError("need at least one value")
    point = statistic(arr)
    if arr.size == 1:
        return Estimate(point, point, point, level)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, arr.size, size=(n_boot, arr.size))
    boot = np.array([statistic(arr[row]) for row in idx])
    lo = float(np.percentile(boot, (1 - level) / 2 * 100))
    hi = float(np.percentile(boot, (1 + level) / 2 * 100))
    return Estimate(point, lo, hi, level)


def wilson_interval(successes: int, n: int, *, level: float = 0.95) -> Estimate:
    if n <= 0:
        raise ValueError("n must be positive")
    if not (0 <= successes <= n):
        raise ValueError("successes must be in [0, n]")
    z = NormalDist().inv_cdf((1 + level) / 2)
    phat = successes / n
    denom = 1.0 + z * z / n
    center = (phat + z * z / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    return Estimate(phat, max(0.0, center - margin), min(1.0, center + margin), level)


def cohens_d(group_a: Sequence[float], group_b: Sequence[float]) -> float:
    a, b = np.asarray(group_a, dtype=float), np.asarray(group_b, dtype=float)
    if a.size < _MIN_GROUP or b.size < _MIN_GROUP:
        raise ValueError("each group needs at least two observations")
    na, nb = a.size, b.size
    pooled_var = ((na - 1) * a.var(ddof=1) + (nb - 1) * b.var(ddof=1)) / (na + nb - 2)
    if pooled_var == 0:
        return 0.0
    return float((a.mean() - b.mean()) / math.sqrt(pooled_var))


def cliffs_delta(group_a: Sequence[float], group_b: Sequence[float]) -> float:
    a, b = np.asarray(group_a, dtype=float), np.asarray(group_b, dtype=float)
    if a.size == 0 or b.size == 0:
        return 0.0
    greater = int((a[:, None] > b[None, :]).sum())
    lesser = int((a[:, None] < b[None, :]).sum())
    return float((greater - lesser) / (a.size * b.size))
