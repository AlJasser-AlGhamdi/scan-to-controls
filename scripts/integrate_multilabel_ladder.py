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


def multilabel_micro_f1(preds: dict, data: dict) -> dict:
    tp = fp = fn = 0.0
    for row in data["checks"]:
        gold = set(row["gold_ids"])
        pred = set(preds.get(row["check"], []) or [])
        w = row["frequency"]
        tp += w * len(pred & gold)
        fp += w * len(pred - gold)
        fn += w * len(gold - pred)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 0.0 if (prec + rec) == 0 else 2 * prec * rec / (prec + rec)
    unanswered = sum(1 for row in data["checks"] if not preds.get(row["check"]))
    return {"micro_f1": round(f1, 4), "precision": round(prec, 4), "recall": round(rec, 4), "unanswered": unanswered}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("fetched_dir")
    args = ap.parse_args()
    fetched = pathlib.Path(args.fetched_dir)

    data = json.loads(DATA.read_text())
    k_results = json.loads((fetched / "baseline_ladder_results.json").read_text())
    k_preds = json.loads((fetched / "baseline_ladder_predictions.json").read_text())
    results = json.loads(RESULTS.read_text())
    preds = json.loads(PREDICTIONS.read_text())

    before_results = json.dumps(results, indent=2)
    before_preds = json.dumps(preds, indent=2)

    added = {}
    mismatch = []
    for model, by_cond in k_preds.items():
        ml = by_cond.get("multi_full_text")
        if ml is None:
            continue
        local = multilabel_micro_f1(ml, data)
        kern = k_results.get(model, {}).get("multi_full_text", {})
        if kern.get("micro_f1") is not None and abs(kern["micro_f1"] - local["micro_f1"]) > 1e-3:
            mismatch.append(f"{model}: kernel {kern['micro_f1']} != local {local['micro_f1']}")
        results.setdefault(model, {})["multi_full_text"] = local
        preds.setdefault(model, {})["multi_full_text"] = ml
        added[model] = local["micro_f1"]

    def _without_ml(d):
        return {m: {k: v for k, v in row.items() if k != "multi_full_text"} for m, row in d.items()}
    assert json.dumps(_without_ml(results), indent=2) == before_results, "single-pick RESULTS changed!"
    assert json.dumps(_without_ml(preds), indent=2) == before_preds, "single-pick PREDICTIONS changed!"

    RESULTS.write_text(json.dumps(results, indent=2))
    PREDICTIONS.write_text(json.dumps(preds, indent=2))

    best = max(added.items(), key=lambda kv: kv[1])
    print(f"added multi_full_text for {len(added)} models; best = {best[0]} {best[1]}")
    for m, f in sorted(added.items(), key=lambda kv: -kv[1]):
        print(f"  {m:24} {f}")
    if mismatch:
        print("MISMATCH vs kernel:", *mismatch, sep="\n  ")
    else:
        print("local recompute matches kernel multi-label aggregates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
