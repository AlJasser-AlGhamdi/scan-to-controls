#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import pathlib
import random
import sys

from p2c.evaluation.tier_second_coder import score_recode
from p2c.mapping.catalog import load_default_index

ROOT = pathlib.Path(__file__).resolve().parent.parent
OVERLAY = ROOT / "taxonomy" / "release" / "sort_overlay.json"
DEFAULT_OUT = ROOT / "private" / "blind_recode_sheet.csv"
SHUFFLE_SEED = 20260812
FIELDS = ["order", "id", "kind", "title", "statement", "assessment_method", "tier"]


def _overlay_rows() -> list[dict]:
    return json.loads(OVERLAY.read_text(encoding="utf-8"))["controls"]


def _arg(flag: str, default: str | None = None) -> str | None:
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default


def generate(out: pathlib.Path) -> None:
    index = load_default_index()
    rows = _overlay_rows()
    order = list(range(len(rows)))
    random.Random(SHUFFLE_SEED).shuffle(order)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        for position, row_idx in enumerate(order, start=1):
            row = rows[row_idx]
            entry = index.require(row["id"])
            writer.writerow(
                {
                    "order": position,
                    "id": row["id"],
                    "kind": row["kind"],
                    "title": entry.title,
                    "statement": entry.statement_en,
                    "assessment_method": entry.assessment_en,
                    "tier": "",
                }
            )
    print(f"wrote {len(rows)} shuffled rows -> {out}")
    print("Fill the `tier` column with 1 (scan provable), 2 (internal assessment), or 3 (declaration).")
    print("This sheet carries NCA control text: keep it under private/, do not commit or send it off host.")
    print(f"When done: uv run python scripts/blind_recode_template.py score --in {out}")


def score(path: pathlib.Path) -> None:
    committed = {r["id"]: int(r["tier"]) for r in _overlay_rows()}
    recoded: dict[str, int] = {}
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            value = (row.get("tier") or "").strip()
            if not value:
                continue
            tier = int(value)
            if tier not in (1, 2, 3):
                raise SystemExit(f"row {row.get('id')}: tier must be 1, 2, or 3, got {value!r}")
            recoded[row["id"]] = tier
    filled, total = len(recoded), len(committed)
    if filled < total:
        print(f"warning: {total - filled} of {total} rows are unfilled; scoring the {filled} filled rows")
    result = score_recode(committed, recoded)
    three, binary = result["threeway"], result["binary"]
    print(f"intra-coder recode over {result['n_rows']} rows")
    print(f"  three way tier: agreement {three['agreement_rate']:.4f}  kappa {three['cohen_kappa']:.4f}")
    print(f"  primary binary: agreement {binary['agreement_rate']:.4f}  kappa {binary['cohen_kappa']:.4f}")
    print(f"  rows moved: {result['n_moved']}")
    for m in result["moved"]:
        print(f"    {m['id']:10s} tier {m['committed_tier']} -> {m['recode_tier']}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "generate"
    if cmd == "generate":
        generate(pathlib.Path(_arg("--out", str(DEFAULT_OUT))))
    elif cmd == "score":
        target = _arg("--in")
        if not target:
            raise SystemExit("score needs --in PATH to the filled sheet")
        score(pathlib.Path(target))
    else:
        raise SystemExit(f"unknown command {cmd}")
