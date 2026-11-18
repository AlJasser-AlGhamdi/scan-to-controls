import json, statistics, math, sys, inspect
sys.path.insert(0, "src")
import numpy as np
from p2c.evaluation.harness import (
    _assert_probabilities, _predict, run_evaluation, stability_across_seeds, generate_cases,
)
from p2c.config import get_settings
seeds = inspect.signature(stability_across_seeds).parameters["seeds"].default
DRAWS, BATCH = 20_000, 2_000


def simulated_expected_f1(cases, seed):
    cells = _assert_probabilities(cases)
    p = np.array([c[0] for c in cells]); t = np.array([c[1] for c in cells])
    rng, f1s = np.random.default_rng(seed), []
    for _ in range(DRAWS // BATCH):
        a = rng.random((BATCH, p.size)) < p
        tp = (a & t).sum(1); fp = (a & ~t).sum(1); fn = t.sum() - tp
        f1s.append(2 * tp / (2 * tp + fp + fn))
    return float(np.concatenate(f1s).mean())


def mapping_mismatches(cases):
    return sum(set(p.predicted) != set(p.observed_gold) for p in _predict(cases))


def expected_f1_unrounded(cases):
    tp = sum(p for p, v in _assert_probabilities(cases) if v)
    fp = sum(p for p, v in _assert_probabilities(cases) if not v)
    fn = sum(1 - p for p, v in _assert_probabilities(cases) if v)
    return 2 * tp / (2 * tp + fp + fn)


pairs = []
for s in seeds:
    r = run_evaluation(100, seed=s)
    cases = generate_cases(100, seed=s)
    expected = expected_f1_unrounded(cases)
    assert abs(expected - r.detection_ceiling["f1"]) < 1e-6, s
    pairs.append({"seed": s, "measured_f1": r.end_to_end["exact_micro"]["f1"], "expected_f1": expected,
                  "simulated_expected_f1": simulated_expected_f1(cases, s),
                  "mapping_mismatches": mapping_mismatches(cases)})
    print(s, *(round(pairs[-1][k], 4) for k in ("measured_f1", "expected_f1", "simulated_expected_f1")), flush=True)
d = [p["measured_f1"] - p["expected_f1"] for p in pairs]
m = [p["measured_f1"] for p in pairs]; e = [p["expected_f1"] for p in pairs]
out = {"seeds": list(seeds), "pairs": pairs,
  "measured_mean": statistics.fmean(m), "measured_pstdev": statistics.pstdev(m), "measured_stdev": statistics.stdev(m),
  "expected_mean": statistics.fmean(e), "expected_pstdev": statistics.pstdev(e),
  "paired_diff_mean": statistics.fmean(d), "paired_diff_stdev": statistics.stdev(d),
  "paired_diff_se": statistics.stdev(d)/math.sqrt(len(d)),
  "n_seeds_measured_above_expected": sum(1 for x in d if x > 0),
  "simulation_draws": DRAWS,
  "mapping_mismatches_total": sum(p["mapping_mismatches"] for p in pairs),
  "count_gap_mean": statistics.fmean(p["simulated_expected_f1"] - p["expected_f1"] for p in pairs),
  "residual_diff_mean": statistics.fmean(rd := [p["measured_f1"] - p["simulated_expected_f1"] for p in pairs]),
  "residual_diff_se": statistics.stdev(rd) / math.sqrt(len(rd)),
  "note": "Per seed: the end-to-end micro F1 on that seed's cohort against the analytic perfect-mapper expectation computed from the same cohort's expected detection counts. The paired difference is the loss (negative) or gain from the mapping and scoring stages plus the seeded draw around the expectation."}
c0 = generate_cases(100, seed=get_settings().global_seed)[0]
out["eval_000_scan_conditions"] = dict(c0.scan_conditions)
json.dump(out, open("evaluation/seed_paired.json","w"), indent=2)
print("paired_diff_mean", out["paired_diff_mean"], "se", out["paired_diff_se"], "above", out["n_seeds_measured_above_expected"])
print("eval-000 conditions", out["eval_000_scan_conditions"])
