#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from p2c.evaluation.harness import reproduce, robustness_report, run_evaluation, write_outputs

OUTPUT_DIR = Path(__file__).resolve().parent / "outputs"


def main() -> None:
    parser = argparse.ArgumentParser(description="ports-to-controls evaluation harness")
    parser.add_argument("--reproduce", action="store_true", help="deterministic regeneration")
    parser.add_argument(
        "--robustness",
        action="store_true",
        help="regenerate the robustness bundle (seeds + detection/attestation/weighting sweeps; slow)",
    )
    parser.add_argument("--n", type=int, default=100, help="number of synthetic profiles")
    parser.add_argument("--seed", type=int, default=None, help="override GLOBAL_SEED")
    parser.add_argument("--out", type=Path, default=OUTPUT_DIR, help="output directory")
    args = parser.parse_args()

    if args.robustness:
        args.out.mkdir(parents=True, exist_ok=True)
        bundle = robustness_report(args.n, seed=args.seed)
        path = args.out / "robustness.json"
        path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        stab = bundle["stability_across_seeds"]
        print(
            f"end to end F1 mean={stab['mean']:.3f} stdev={stab['stdev']:.3f} over {len(stab['seeds'])} seeds"
        )
        print(f"weighting: assessed mean|delta|={bundle['weighting']['assessed_mean_abs_delta']:.3f}")
        print(f"robustness -> {path}")
        return

    if args.reproduce:
        report = reproduce(args.out, n=args.n, seed=args.seed)
    else:
        report = run_evaluation(args.n, seed=args.seed)
        write_outputs(report, args.out)

    m = report.mapping["exact_micro"]
    e = report.end_to_end["exact_micro"]
    d = report.detection
    print(
        f"profiles={report.n_profiles} observed={report.n_findings} "
        f"true={report.n_true_findings} seed={report.seed}"
    )
    print(f"mapping integrity F1={m['f1']:.3f} (correct by construction)")
    print(f"end to end  P={e['precision']:.3f} R={e['recall']:.3f} F1={e['f1']:.3f}")
    print(
        f"detection: detected={d['n_detected']} missed={d['n_missed']} "
        f"false_alarm={d['n_false_alarm']} (recall {d['recall']:.3f})"
    )
    print(f"outputs -> {args.out}")


if __name__ == "__main__":
    main()
