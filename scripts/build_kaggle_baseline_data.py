#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

from p2c.evaluation.ablation import check_query_text, subcontrol_entries, subcontrol_text_full
from p2c.evaluation.synthetic import expert_key, generate_cases

ARABIC = re.compile(r"[؀-ۿݐ-ݿ]")
NOTE = (
    "ATLAS ECC-mapping baseline, portable (synthetic only, no real data). Score = micro-F1 of "
    "predicted control id vs gold, pooled over checks weighted by observed frequency in the "
    "n=100 seed=1337 corpus."
)


def build(n: int = 100, seed: int = 1337) -> dict:
    entries = subcontrol_entries()
    valid_ids = [e.native_id for e in entries]
    catalog_title = {e.native_id: e.title for e in entries}
    catalog_full = {e.native_id: subcontrol_text_full(e) for e in entries}

    key = expert_key()
    freq = Counter(inj.check for c in generate_cases(n, seed=seed) for inj in c.injected)
    checks = []
    for check in sorted(key, key=lambda c: c.value):
        gold = sorted(key[check])
        count = freq.get(check, 0)
        if not gold or not count:
            continue
        checks.append(
            {
                "check": check.value,
                "query_text": check_query_text(check),
                "gold_ids": gold,
                "frequency": count,
            }
        )
    return {
        "note": NOTE,
        "valid_ids": valid_ids,
        "catalog_title": catalog_title,
        "catalog_full": catalog_full,
        "checks": checks,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="evaluation/kaggle_baseline_data.json")
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    data = build(args.n, args.seed)
    text = json.dumps(data, ensure_ascii=False, indent=2)
    if ARABIC.search(text):
        raise SystemExit("ARABIC CODEPOINT IN KAGGLE DATA: copyright stop, refusing to write")
    Path(args.out).write_text(text, encoding="utf-8")
    total = sum(c["frequency"] for c in data["checks"])
    print(
        f"wrote {args.out}: {len(data['valid_ids'])} candidate controls, {len(data['checks'])} "
        f"checks, {total} weighted findings (n={args.n}, seed={args.seed}); zero Arabic codepoints"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
