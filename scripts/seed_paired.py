import json, statistics, math, sys, inspect
sys.path.insert(0, "src")
from p2c.evaluation.harness import run_evaluation, stability_across_seeds, generate_cases
from p2c.config import get_settings
seeds = inspect.signature(stability_across_seeds).parameters["seeds"].default
pairs = []
for s in seeds:
    r = run_evaluation(100, seed=s)
    pairs.append({"seed": s, "measured_f1": r.end_to_end["exact_micro"]["f1"], "expected_f1": r.detection_ceiling["f1"]})
    print(s, round(pairs[-1]["measured_f1"],4), round(pairs[-1]["expected_f1"],4), flush=True)
d = [p["measured_f1"] - p["expected_f1"] for p in pairs]
m = [p["measured_f1"] for p in pairs]; e = [p["expected_f1"] for p in pairs]
out = {"seeds": list(seeds), "pairs": pairs,
  "measured_mean": statistics.fmean(m), "measured_pstdev": statistics.pstdev(m), "measured_stdev": statistics.stdev(m),
  "expected_mean": statistics.fmean(e), "expected_pstdev": statistics.pstdev(e),
  "paired_diff_mean": statistics.fmean(d), "paired_diff_stdev": statistics.stdev(d),
  "paired_diff_se": statistics.stdev(d)/math.sqrt(len(d)),
  "n_seeds_measured_above_expected": sum(1 for x in d if x > 0),
  "note": "Per seed: the end-to-end micro F1 on that seed's cohort against the analytic perfect-mapper expectation computed from the same cohort's expected detection counts. The paired difference is the loss (negative) or gain from the mapping and scoring stages plus the seeded draw around the expectation."}
c0 = generate_cases(100, seed=get_settings().global_seed)[0]
out["eval_000_scan_conditions"] = dict(c0.scan_conditions)
json.dump(out, open("evaluation/seed_paired.json","w"), indent=2)
print("paired_diff_mean", out["paired_diff_mean"], "se", out["paired_diff_se"], "above", out["n_seeds_measured_above_expected"])
print("eval-000 conditions", out["eval_000_scan_conditions"])
