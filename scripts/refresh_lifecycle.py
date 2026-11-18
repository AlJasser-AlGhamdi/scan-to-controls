#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from datetime import UTC, datetime

import httpx

ROOT = pathlib.Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "src" / "p2c" / "scanning" / "data" / "lifecycle.json"
_FIELDS = ("cycle", "latest", "eol", "releaseDate")
_VERSION = re.compile(r"\d+(?:\.\d+)*")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def cycles(raw: object, product: str) -> list[dict[str, object]]:
    if not isinstance(raw, list) or not raw:
        raise SystemExit(f"{product}: the source returned no release cycles")
    out = []
    for entry in raw:
        versions = isinstance(entry, dict) and all(
            isinstance(entry.get(f), str) and _VERSION.fullmatch(entry[f]) for f in ("cycle", "latest")
        )
        if not versions:
            raise SystemExit(f"{product}: a cycle without a dotted name or latest patch: {entry!r}")
        eol = entry.get("eol")
        if not (isinstance(eol, bool) or (isinstance(eol, str) and _DATE.fullmatch(eol))):
            raise SystemExit(f"{product}: cycle {entry['cycle']} has no end-of-life flag or ISO date")
        out.append({field: entry.get(field) for field in _FIELDS})
    return out


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def patch_dates(
    cycle: dict[str, object], versions: dict[str, dict[str, str]], product: str
) -> dict[str, str]:
    head, latest = _version(str(cycle["cycle"])), _version(str(cycle["latest"]))
    dates = {
        name: entry["date"]
        for name, entry in versions.items()
        if isinstance(entry, dict)
        and _VERSION.fullmatch(name)
        and _version(name)[: len(head)] == head
        and _version(name) <= latest
        and _DATE.fullmatch(str(entry.get("date")))
    }
    if str(cycle["latest"]) not in dates:
        raise SystemExit(
            f"{product}: the release data has no date for {cycle['latest']}; it may lag the cycle "
            "source, so retry later"
        )
    return dict(sorted(dates.items(), key=lambda item: _version(item[0])))


def _supported(cycle: dict[str, object], today: str) -> bool:
    return cycle["eol"] is False or (isinstance(cycle["eol"], str) and cycle["eol"] > today)


def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out", type=pathlib.Path, default=SNAPSHOT)
    args = parser.parse_args(argv)
    doc = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    with httpx.Client(timeout=30.0, trust_env=False, follow_redirects=True) as client:
        products = {}
        today = datetime.now(UTC).date().isoformat()
        for product in doc["products"]:
            response = client.get(doc["source"].replace("<product>", product))
            response.raise_for_status()
            products[product] = cycles(response.json(), product)
            response = client.get(doc["patch_source"].replace("<product>", product))
            response.raise_for_status()
            versions = response.json().get("versions")
            if not isinstance(versions, dict):
                raise SystemExit(f"{product}: the release data has no versions map")
            for cycle in products[product]:
                if _supported(cycle, today):
                    cycle["patches"] = patch_dates(cycle, versions, product)
    doc["products"], doc["retrieved"] = products, today
    doc["patches_retrieved"] = today
    args.out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"{', '.join(products)} refreshed on {doc['retrieved']} -> {args.out}")


if __name__ == "__main__":
    main(sys.argv[1:])
