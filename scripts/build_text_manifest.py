#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
from typing import Any

from p2c.sovereignty.provenance import canonical_arabic, text_fingerprint

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOGS = (
    ROOT / "private" / "catalogs" / "ecc-2-2024.json",
    ROOT / "private" / "catalogs" / "ncnicc-1-2025.json",
)
OUT = ROOT / "taxonomy" / "release" / "text_manifest.json"
_CDN = "https://cdn.nca.gov.sa/api/files/public/upload/"
SOURCES = {
    "nca-pdf": (
        "NCA, Essential Cybersecurity Controls (ECC-2:2024), Arabic edition: "
        f"{_CDN}da829b21-c4ef-4a6e-9f6e-82690d612ee9_ECC-2-2024-.pdf"
    ),
    "gecc-2026-guide": (
        "NCA, Guide to Essential Cybersecurity Controls Implementation (GECC-2:2026), Arabic text (its "
        f"English edition: {_CDN}11bb8f2d-706a-4f18-80f1-40d620ebd845_GECC-.pdf); most of its pages carry "
        "no text layer, so these rows were transcribed from the page images, and a mismatch may be a "
        "transcription slip of ours"
    ),
    "ncnicc-md": (
        "NCA, Non-Critical National Infrastructure Cybersecurity Controls (NCNICC-1:2025), Arabic: "
        f"{_CDN}721bed5c-5304-497c-a5ac-a92a049e6306_NCNICC-AR-.pdf"
    ),
}


def rows(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            parts = node.get("parts") if "id" in node else None
            arabic = [p for p in parts or [] if isinstance(p, dict) and p.get("class") == "ar"]
            if arabic:
                text = " ".join(str(p.get("prose", "")) for p in arabic)
                source = next(
                    (
                        pr["value"]
                        for p in arabic
                        for pr in p.get("props", [])
                        if pr.get("name") == "translation-status"
                    ),
                    "unknown",
                )
                found.append(
                    {
                        "id": str(node["id"]).split("-", 1)[1],
                        "sha256": text_fingerprint(text),
                        "words": len(canonical_arabic(text).split()),
                        "source": source,
                    }
                )
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(catalog)
    return found


def main() -> None:
    entries = [row for path in CATALOGS for row in rows(json.loads(path.read_text(encoding="utf-8")))]
    overlay = {
        c["id"]
        for c in json.loads(
            (ROOT / "taxonomy" / "release" / "sort_overlay.json").read_text(encoding="utf-8")
        )["controls"]
    }
    if {e["id"] for e in entries} != overlay or len(entries) != len(overlay):
        raise SystemExit("the catalogues' Arabic rows do not match the 204 overlay rows one to one")
    if unknown := sorted({e["source"] for e in entries} - set(SOURCES)):
        raise SystemExit(f"rows from an unlisted source: {unknown}")
    manifest = {
        "about": (
            "SHA-256 of each row's Arabic statement in canonical form (normalised letters and digits, one "
            "space between words); check with scripts/verify_against_nca.py"
        ),
        "sources": SOURCES,
        "rows": sorted(entries, key=lambda e: [int(x) for x in e["id"].split("-")]),
    }
    OUT.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{len(entries)} rows -> {OUT}")


if __name__ == "__main__":
    main()
