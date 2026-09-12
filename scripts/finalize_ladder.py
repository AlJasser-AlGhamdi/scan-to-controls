#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVAL = ROOT / "evaluation"
DATA = EVAL / "kaggle_baseline_data.json"
RESULTS = EVAL / "baseline_ladder_results.json"
PREDICTIONS = EVAL / "baseline_ladder_predictions.json"
PROVENANCE = EVAL / "kaggle_provenance.json"


def micro_f1(preds: dict, data: dict) -> dict:
    tp = fp = fn = 0
    for row in data["checks"]:
        gold = set(row["gold_ids"])
        pred = {preds[row["check"]]} if preds.get(row["check"]) else set()
        w = row["frequency"]
        tp += w * len(pred & gold)
        fp += w * len(pred - gold)
        fn += w * len(gold - pred)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 0.0 if (prec + rec) == 0 else 2 * prec * rec / (prec + rec)
    unanswered = sum(1 for row in data["checks"] if not preds.get(row["check"]))
    return {
        "micro_f1": round(f1, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "unanswered": unanswered,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("fetched_dir")
    ap.add_argument("--notebook-url", default="https://www.kaggle.com/code/aljasseralghmadi/p2c-baseline-ladder")
    ap.add_argument("--slug", default="aljasseralghmadi/p2c-baseline-ladder")
    args = ap.parse_args()

    fetched = pathlib.Path(args.fetched_dir)
    data = json.loads(DATA.read_text(encoding="utf-8"))
    k_results = json.loads((fetched / "baseline_ladder_results.json").read_text())
    k_preds = json.loads((fetched / "baseline_ladder_predictions.json").read_text())
    k_prov = json.loads((fetched / "kaggle_provenance.json").read_text())
    stored = json.loads(RESULTS.read_text(encoding="utf-8")) if RESULTS.is_file() else {}

    fresh_results: dict = {}
    fresh_status: dict = {}
    mismatch: list = []
    for model, preds_by_cond in k_preds.items():
        entry: dict = {}
        for cond in ("title", "full_text"):
            if cond not in preds_by_cond:
                continue
            local = micro_f1(preds_by_cond[cond], data)
            entry[cond] = local
            kern = k_results.get(model, {}).get(cond, {})
            if kern.get("micro_f1") is not None and abs(kern["micro_f1"] - local["micro_f1"]) > 1e-9:
                mismatch.append(f"{model}/{cond}: kernel {kern['micro_f1']} != local {local['micro_f1']}")
        if "secs" in k_results.get(model, {}):
            entry["secs"] = k_results[model]["secs"]
        if entry:
            fresh_results[model] = entry
            fresh_status[model] = "fresh"

    merged = dict(stored)
    merged.update(fresh_results)
    for model in merged:
        if model not in fresh_status:
            fresh_status[model] = "stored_stale"

    RESULTS.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    PREDICTIONS.write_text(json.dumps(k_preds, indent=2), encoding="utf-8")

    ran = sorted(m for m, s in fresh_status.items() if s == "fresh")
    stale = sorted(m for m, s in fresh_status.items() if s == "stored_stale")
    best_fresh = max(
        (v["full_text"]["micro_f1"] for m, v in fresh_results.items() if v.get("full_text")), default=None
    )
    best_overall = max((v["full_text"]["micro_f1"] for v in merged.values() if v.get("full_text")), default=None)

    provenance = {
        "notebook_url": args.notebook_url,
        "kernel_slug": args.slug,
        "run": k_prov,
        "model_status": fresh_status,
        "models_fresh": ran,
        "models_stale_prior": stale,
        "best_full_text_f1_fresh": best_fresh,
        "best_full_text_f1_overall": best_overall,
        "single_pick_ceiling_note": "computed locally from baselines.json (single_pick_ceiling), not on Kaggle",
        "local_vs_kernel_mismatches": mismatch,
        "data_sha256_expected": k_prov.get("data_sha256"),
    }
    PROVENANCE.write_text(json.dumps(provenance, indent=2), encoding="utf-8")

    print(f"fresh models ({len(ran)}): {ran}")
    print(f"stale/prior models ({len(stale)}): {stale}")
    print(f"best full_text F1 fresh={best_fresh}  overall={best_overall}  -> rounds to {round(best_overall,2) if best_overall else None}")
    if mismatch:
        print("LOCAL vs KERNEL MISMATCHES:")
        for m in mismatch:
            print("  x", m)
    else:
        print("local recompute matches kernel aggregates exactly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
