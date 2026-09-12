#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TEX = ROOT / "spec" / "atlas_taxonomy_v4.tex"
OUT_DIR = ROOT / "catalogs" / "_source"

DOMAINS = {
    "1": "Cybersecurity Governance",
    "2": "Cybersecurity Defense",
    "3": "Cybersecurity Resilience",
    "4": "Third-Party and Cloud Computing Cybersecurity",
}

_TIER = {r"\tone": 1, r"\ttwo": 2, r"\tthree": 3}
_ROW_COLS = 8
_SUBCONTROL_HYPHENS = 3
_ROW_ID = re.compile(r"^(\d-\d+-\d+(?:-\d+)?)\s")
_SUBDOMAIN_HDR = re.compile(r"\\multicolumn\{8\}\{l\}\{\\textit\{(\d-\d+)\s+([^}]+)\}\}")
_NCNICC_REF = re.compile(r"(\d+-\d+)\s*\((M|R)\)")
_CELLCOLOR = re.compile(r"\\cellcolor\{[^}]*\}")


_MATH = ((r"\geq", "≥"), (r"\leq", "≤"), (r"\approx", "≈"), (r"\times", "×"), (r"\ge", "≥"), (r"\le", "≤"))


def _clean(text: str) -> str:
    text = text.strip()
    text = _CELLCOLOR.sub("", text)
    text = re.sub(r"\\(?:texttt|emph|textbf|textit)\{([^}]*)\}", r"\1", text)
    text = re.sub(r"\\makecell\[[^]]*\]\{([^}]*)\}", r"\1", text)
    for src, dst in _MATH:
        text = text.replace(src, dst)
    text = text.replace("$", "")
    for src, dst in (
        (r"\_", "_"),
        (r"\&", "&"),
        (r"\%", "%"),
        (r"\#", "#"),
        (r"\,", " "),
        ("\\ ", " "),
        ("~", " "),
    ):
        text = text.replace(src, dst)
    text = text.replace(r"\emph", "")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _parse_tier(cell: str) -> int:
    for macro, value in _TIER.items():
        if macro in cell:
            return value
    raise ValueError(f"no tier macro in cell: {cell!r}")


def _parse_ncnicc(cell: str) -> dict[str, str] | None:
    cell = cell.strip()
    if "N/A" in cell or not cell:
        return None
    match = _NCNICC_REF.search(cell)
    if match is None:
        return None
    return {"subcomponent": match.group(1), "status": match.group(2)}


def _split_row(line: str) -> list[str]:
    body = line.rstrip()
    if body.endswith(r"\\"):
        body = body[:-2]
    return [c.strip() for c in body.split("&")]


def _parse_main_table(lines: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    subdomain_id = subdomain_title = ""
    for line in lines:
        hdr = _SUBDOMAIN_HDR.search(line)
        if hdr is not None:
            subdomain_id, subdomain_title = hdr.group(1), _clean(hdr.group(2))
            continue
        if not _ROW_ID.match(line):
            continue
        cells = _split_row(line)
        if len(cells) != _ROW_COLS:
            continue
        cid = cells[0].strip()
        domain_id = cid.split("-", 1)[0]
        records.append(
            {
                "id": cid,
                "kind": "subcontrol" if cid.count("-") == _SUBCONTROL_HYPHENS else "main",
                "domain": domain_id,
                "domain_title": DOMAINS[domain_id],
                "subdomain": subdomain_id,
                "subdomain_title": subdomain_title,
                "clause_en": _clean(cells[1]),
                "method_en": _clean(cells[2]),
                "tier": _parse_tier(cells[3]),
                "reading_en": _clean(cells[4]),
                "remediation_en": _clean(cells[5]),
                "ncnicc_class_a": _parse_ncnicc(cells[6]),
                "ncnicc_class_b": _parse_ncnicc(cells[7]),
            }
        )
    return records


def _parse_ncnicc_exclusive(lines: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in lines:
        if not line.startswith("NCNICC "):
            continue
        cells = _split_row(line)
        if len(cells) != _ROW_COLS:
            continue
        cid = cells[0].replace("NCNICC", "").strip()
        records.append(
            {
                "id": cid,
                "kind": "ncnicc_exclusive",
                "class_a": "M" if "M" in _clean(cells[1]) else "R",
                "class_b": "M" if "M" in _clean(cells[2]) else "R",
                "clause_en": _clean(cells[3]),
                "clause_en_source": "atlas-taxonomy-summary",
                "method_en": _clean(cells[4]),
                "tier": _parse_tier(cells[5]),
                "reading_en": _clean(cells[6]),
                "remediation_en": _clean(cells[7]),
            }
        )
    return records


def main() -> None:
    lines = TEX.read_text(encoding="utf-8").splitlines()
    ecc = _parse_main_table(lines)
    ncnicc = _parse_ncnicc_exclusive(lines)
    print(f"ATLAS-metadata rows: {len(ecc)} ECC + {len(ncnicc)} NCNICC-exclusive (preview; no writes).")
    print("Primary source is now the NCA PDFs — run scripts/extract_regulations.py.")


if __name__ == "__main__":
    main()
