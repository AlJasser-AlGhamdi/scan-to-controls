#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVAL = ROOT / "evaluation"
DATA = EVAL / "kaggle_baseline_data.json"
RESULTS = EVAL / "baseline_ladder_results.json"
PREDICTIONS = EVAL / "baseline_ladder_predictions.json"


def micro(preds: dict[str, object], data: dict) -> dict:
    tp = fp = fn = 0.0
    unanswered = 0
    for row in data["checks"]:
        gold = set(row["gold_ids"])
        raw = preds.get(row["check"])
        if not raw:
            pred: set[str] = set()
            unanswered += 1
        elif isinstance(raw, str):
            pred = {raw}
        else:
            pred = set(raw)
        w = row["frequency"]
        tp += w * len(pred & gold)
        fp += w * len(pred - gold)
        fn += w * len(gold - pred)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 0.0 if (prec + rec) == 0 else 2 * prec * rec / (prec + rec)
    return {
        "micro_f1": round(f1, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "unanswered": unanswered,
    }


def main() -> int:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    predictions = json.loads(PREDICTIONS.read_text(encoding="utf-8"))
    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    for model, conditions in predictions.items():
        entry = results.setdefault(model, {})
        for condition, preds in conditions.items():
            entry[condition] = micro(preds, data)
    RESULTS.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    best = max((s["full_text"]["micro_f1"], m) for m, s in results.items() if s.get("full_text"))
    multi = max((s["multi_full_text"]["micro_f1"], m) for m, s in results.items() if s.get("multi_full_text"))
    n = sum(r["frequency"] for r in data["checks"])
    print(f"rescored {len(predictions)} models under {n} weighted findings")
    print(f"best full_text: {best[1]} {best[0]}; best multi_full_text: {multi[1]} {multi[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
