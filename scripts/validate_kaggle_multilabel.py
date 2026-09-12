#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
KERNEL = ROOT / "evaluation" / "kaggle_kernel" / "kaggle_run.py"
DATA = json.loads((ROOT / "evaluation" / "kaggle_baseline_data.json").read_text(encoding="utf-8"))


def _load_kernel():
    spec = importlib.util.spec_from_file_location("kaggle_run_template", KERNEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod._IS_TEMPLATE, "expected the tracked template with the __DATA_B64__ placeholder"
    mod.VALID = set(DATA["valid_ids"])
    return mod


def _unit_checks(k) -> None:
    valid = set(DATA["valid_ids"])
    a_multi = sorted(c for c in valid if c.startswith("2-2-3"))[:2]
    assert len(a_multi) >= 2, "need a two-id example from the catalog"
    resp = f"The finding evidences {a_multi[0]} and also {a_multi[1]}, and again {a_multi[0]}."
    got = k.extract_ids(resp, "")
    assert set(got) == set(a_multi) and len(got) == 2, f"extract_ids dedupe failed: {got}"
    assert k.extract_ids("no id here", "") == [], "extract_ids should return [] on no id"
    checks = [{"check": "x", "gold_ids": a_multi, "frequency": 3}]
    perfect = k.micro_f1({"x": a_multi}, checks=checks, multi=True)
    assert perfect["micro_f1"] == 1.0, f"perfect multi-label should be 1.0: {perfect}"
    half = k.micro_f1({"x": [a_multi[0]]}, checks=checks, multi=True)
    assert abs(half["micro_f1"] - round(2 / 3, 4)) < 1e-9, f"partial multi-label wrong: {half}"
    print(f"unit checks ok: extract_ids dedupe, micro_f1 multi (perfect={perfect['micro_f1']}, "
          f"half={half['micro_f1']})")


def _model_checks(k) -> None:
    block = "\n".join(f"{cid}: {txt}" for cid, txt in DATA["catalog_full"].items())
    sample = [row for row in DATA["checks"] if len(row["gold_ids"]) > 1][:2]
    preds: dict[str, list[str]] = {}
    for row in sample:
        prompt = (
            f"Scan finding: {row['query_text']}\n\n"
            f"Candidate controls (id: text):\n{block}\n\n"
            "List every applicable control id, one per line, and nothing else."
        )
        resp, think = k.ollama_generate("qwen2.5:7b", prompt, 8192, 900.0, k.SYSTEM_MULTI)
        ids = k.extract_ids(resp, think)
        preds[row["check"]] = ids
        print(f"  {row['check']:26s} gold={row['gold_ids']}  pred={ids}")
    agg = k.micro_f1(preds, checks=sample, multi=True)
    print(f"multi-label micro_f1 over {len(sample)} multi-gold checks = {agg}")


if __name__ == "__main__":
    kernel = _load_kernel()
    _unit_checks(kernel)
    _model_checks(kernel)
    print("kaggle multi-label path validated locally; DO NOT push (human runs the GPU ladder).")
