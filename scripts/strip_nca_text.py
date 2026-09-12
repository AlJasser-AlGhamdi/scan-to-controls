#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re
import shutil
import sys

ARABIC = re.compile(r"[؀-ۿݐ-ݿ]")

STUB = """# Regulation sources withheld

The raw NCA regulation sources (PDF, DOCX, and extracted markdown, including the legally
binding Arabic text) are withheld from this artifact pending NCA permission. The English
ECC-2:2024 document is openly published by the NCA at the URL cited in the manuscript.
The machine readable encoding derived from these sources ships in catalogs/.
"""


def strip_catalog(path: pathlib.Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))

    def walk(node: object) -> object:
        if isinstance(node, dict):
            if "parts" in node and isinstance(node["parts"], list):
                node["parts"] = [p for p in node["parts"] if p.get("class") != "ar"]
            if "props" in node and isinstance(node["props"], list):
                node["props"] = [p for p in node["props"] if not p.get("name", "").endswith("-ar")]
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    path.write_text(json.dumps(walk(data), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def strip_source(path: pathlib.Path) -> None:
    records = json.loads(path.read_text(encoding="utf-8"))
    for record in records:
        for key in [k for k in record if "_ar" in k]:
            record[key] = "withheld pending NCA permission"
    path.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    staging = pathlib.Path(sys.argv[1])
    for name in ["ecc-2-2024.json", "ncnicc-1-2025.json"]:
        strip_catalog(staging / "catalogs" / name)
    for name in ["ecc_records.json", "ncnicc_exclusive.json"]:
        strip_source(staging / "catalogs" / "_source" / name)
    regulations = staging / "spec" / "regulations"
    if regulations.exists():
        shutil.rmtree(regulations)
    regulations.mkdir()
    (regulations / "README.md").write_text(STUB, encoding="utf-8")

    leaks = []
    for scope in ["catalogs", "spec"]:
        for f in (staging / scope).rglob("*"):
            if f.is_file() and ARABIC.search(f.read_text(encoding="utf-8", errors="ignore")):
                leaks.append(str(f.relative_to(staging)))
    if leaks:
        print("BINDING TEXT SURVIVES THE STRIP:")
        for leak in leaks:
            print("  x", leak)
        return 1
    print("  binding NCA text stripped; zero Arabic codepoints under catalogs/ and spec/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
