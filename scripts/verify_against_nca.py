#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import pathlib
import sys
from typing import Any

from p2c.sovereignty.provenance import canonical_arabic, text_fingerprint

MANIFEST = pathlib.Path(__file__).resolve().parent.parent / "taxonomy" / "release" / "text_manifest.json"


def verify(texts: dict[str, str], manifest: dict[str, Any]) -> dict[str, list[str]]:
    rows = {str(r["id"]): r for r in manifest["rows"]}
    out: dict[str, list[str]] = {"match": [], "differ": [], "not_given": [], "unknown_id": []}
    for cid, text in texts.items():
        if cid not in rows:
            out["unknown_id"].append(cid)
        elif text_fingerprint(text) == rows[cid]["sha256"]:
            out["match"].append(cid)
        else:
            out["differ"].append(
                f"{cid} (yours {len(canonical_arabic(text).split())} words, ours {rows[cid]['words']})"
            )
    out["not_given"] = sorted(set(rows) - set(texts))
    return out


def main(argv: list[str]) -> None:
    if "--texts" not in argv:
        raise SystemExit(__doc__)
    path = pathlib.Path(argv[argv.index("--texts") + 1])
    with path.open(encoding="utf-8-sig", newline="") as fh:
        texts = {row["id"].strip(): row["text"] for row in csv.DictReader(fh)}
    result = verify(texts, json.loads(MANIFEST.read_text(encoding="utf-8")))
    counts = {label: len(result[label]) for label in ("match", "differ", "not_given")}
    print(f"{counts['match']} rows match, {counts['differ']} differ, {counts['not_given']} not given")
    for label in ("differ", "unknown_id"):
        for item in result[label]:
            print(f"  {label}: {item}")
    if result["differ"] or result["unknown_id"]:
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
