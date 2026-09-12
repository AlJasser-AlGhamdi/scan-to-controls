#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REG = ROOT / "spec" / "regulations"
OUT_DIR = ROOT / "catalogs" / "_source"
ECC_EN_PDF = REG / "ECC--2024-EN.pdf"
ECC_AR_PDF = REG / "ECC-2-2024---NCA.pdf"
GECC_AR_MD = REG / "GECC_2_2026_faithful_extract.md"
NCNICC_AR_MD = REG / "NCNICC-1-2025-clean-Arabic.md"

DOMAINS = {
    "1": "Cybersecurity Governance",
    "2": "Cybersecurity Defense",
    "3": "Cybersecurity Resilience",
    "4": "Third-Party and Cloud Computing Cybersecurity",
}

_NOISE = (
    "Essential Cybersecurity Controls",
    "Document classification",
    "TLP: White",
    "مقيد",
    "محدود",
    "ﻣﻘﻴﺪ",
    "ﻣحﺪود",
    "الضوابط الأساسية للأمن السيبراني",
)
_DOMAIN_TITLE_LINES = frozenset(DOMAINS.values())
_STOP = re.compile(r"^(Objective|Controls|Appendices|Appendix)\b|^\d[.-]\d{1,2}(\s|$)")
_ID_MAIN = re.compile(r"^(\d-\d{1,2}-\d{1,2})(?![\d.-])")
_ID_SUB = re.compile(r"^(\d[.-]\d{1,2}[.-]\d{1,2}[.-]\d{1,2})(?![\d.-])")
_AR_DIGITS = {ord(a): ord(la) for a, la in zip("٠١٢٣٤٥٦٧٨٩", "0123456789", strict=True)}


def _pages(path: Path) -> list[str]:
    import fitz

    doc = fitz.open(path)
    return [doc[i].get_text() for i in range(doc.page_count)]


def _detail_pages(pages: list[str]) -> list[str]:
    end = next((i for i, t in enumerate(pages) if "Previous text" in t and "Updated text" in t), len(pages))
    return pages[:end]


def _clean_lines(text: str) -> list[str]:
    out: list[str] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or any(n in s for n in _NOISE) or re.fullmatch(r"\d{1,3}", s):
            continue
        if s in _DOMAIN_TITLE_LINES:
            continue
        out.append(s)
    return out


def _norm_sub_id(raw: str) -> str:
    return raw.replace(".", "-")


def parse_ecc_english() -> list[dict[str, Any]]:
    lines: list[str] = []
    for page in _detail_pages(_pages(ECC_EN_PDF)):
        lines += _clean_lines(page)

    records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    def flush() -> None:
        nonlocal current
        if current is not None:
            text = re.sub(r"\s+", " ", current["text_en"]).strip()
            text = re.sub(r"([A-Za-z])-\s+([A-Za-z])", r"\1-\2", text)
            current["text_en"] = text
            records.append(current)
            current = None

    for line in lines:
        m_main = _ID_MAIN.match(line)
        m_sub = _ID_SUB.match(line)
        if m_sub:
            flush()
            cid = _norm_sub_id(m_sub.group(1))
            current = {"id": cid, "kind": "sub", "text_en": line[m_sub.end() :].strip()}
        elif m_main:
            flush()
            current = {"id": m_main.group(1), "kind": "main", "text_en": line[m_main.end() :].strip()}
        elif current is not None:
            if _STOP.match(line):
                flush()
            else:
                current["text_en"] += " " + line
    flush()

    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for r in records:
        if r["id"] in seen or not _valid_id(r["id"]):
            continue
        seen.add(r["id"])
        parts = r["id"].split("-")
        r["domain"] = parts[0]
        r["domain_title"] = DOMAINS[parts[0]]
        r["subdomain"] = "-".join(parts[:2])
        unique.append(r)
    return unique


def _valid_id(cid: str) -> bool:
    parts = cid.split("-")
    return len(parts) in (3, 4) and all(p.isdigit() for p in parts) and parts[0] in DOMAINS


_GLYPH_FIX = {
    "˻": "ني",
    "˴": "ما",
    "˼": "ير",
    "˾": "ين",
    "ɬ": "بم",
    "˺": "نى",
    "˽": "يم",
    "ˮ": "لم",
    "ɧ": "ئم",
    "˹": "نم",
    "ɵ": "ثر",
    "ɱ": "تم",
    "ʗ": "كي",
    "ɴ": "تي",
    "ɪ": "ئي",
    "": " ",
    "“": '"',
    "”": '"',
}
_ALLOWED_EXTRA = set(" \n\t.,:;()[]{}«»\"'-/–%،؛؟•")


def _fix_arabic(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(_AR_DIGITS)
    for bad, good in _GLYPH_FIX.items():
        text = text.replace(bad, good)
    return text


def _arabic_is_clean(text: str) -> bool:
    for ch in text:
        o = ord(ch)
        if 0x0600 <= o <= 0x06FF or ch in _ALLOWED_EXTRA or ch.isdigit() or ("a" <= ch.lower() <= "z"):
            continue
        return False
    return True


_AR_LINE_ID = re.compile(r"^(.*?)(\d-\d{1,2}(?:-\d{1,2}){0,2})\s*$")
_COMBINING = "ً-ْ"


def _normalize_ar_id(cid: str, valid_ids: set[str]) -> str | None:
    if cid in valid_ids:
        return cid
    parts = cid.split("-")
    if len(parts) >= 2:
        parts[1] = parts[1][::-1]
        candidate = "-".join(parts)
        if candidate in valid_ids:
            return candidate
    return None


def _clean_arabic_text(text: str) -> str:
    text = re.sub(r"\([^)]*\)", "", text)
    text = re.sub(r"[A-Za-z]", "", text)
    text = text.replace(".", " ")
    text = re.sub(rf"\s+[{_COMBINING}]+", " ", text)
    return re.sub(r"\s+", " ", text).strip(" ،:؛-")


def parse_ecc_arabic(valid_ids: set[str]) -> dict[str, str]:
    lines: list[str] = []
    for page in _detail_pages(_pages(ECC_AR_PDF)):
        lines += _clean_lines(_fix_arabic(page))

    out: dict[str, str] = {}
    for line in lines:
        m = _AR_LINE_ID.match(line)
        if m is None:
            continue
        cid = _normalize_ar_id(m.group(2), valid_ids)
        if cid is None or cid in out:
            continue
        text = _clean_arabic_text(m.group(1))
        if text.startswith("يجب") and 12 <= len(text) <= 600 and _arabic_is_clean(text):
            out[cid] = text
    return out


_GECC_STMT = re.compile(
    r"\*\*(\d{1,2}(?:-\d{1,2}){2,3})\*\*\s*[—–-]*\s*(.+?)(?=\n\s*\n|\n\s*\*\*)", re.DOTALL
)


def parse_gecc_arabic(valid_ids: set[str], *, md_text: str | None = None) -> dict[str, str]:
    if md_text is None:
        md_text = GECC_AR_MD.read_text(encoding="utf-8") if GECC_AR_MD.exists() else ""
    out: dict[str, str] = {}
    for m in _GECC_STMT.finditer(md_text):
        cid = "-".join(reversed(m.group(1).split("-")))
        if cid not in valid_ids or cid in out:
            continue
        stmt = re.sub(r"\s+", " ", m.group(2)).strip(" ،:؛-—–")
        arabic_chars = sum(1 for ch in stmt if 0x0600 <= ord(ch) <= 0x06FF)
        if 20 <= len(stmt) <= 1500 and arabic_chars >= 0.4 * len(stmt):
            out[cid] = stmt
    return out


_NCNICC_ROW = re.compile(r"^\|\s*(\d(?:-\d{1,2}){3})\s*\|\s*([^|]+?)\s*\|", re.M)


def parse_ncnicc_arabic(valid_ids: set[str], *, md_text: str | None = None) -> dict[str, str]:
    if md_text is None:
        md_text = NCNICC_AR_MD.read_text(encoding="utf-8") if NCNICC_AR_MD.exists() else ""
    out: dict[str, str] = {}
    for nid, ar in _NCNICC_ROW.findall(md_text):
        cid = "-".join(reversed(nid.split("-")))
        text = ar.strip()
        if cid in valid_ids and cid not in out and len(text) > 15:
            out[cid] = text
    return out


def _tex_metadata() -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    import extract_taxonomy as tax

    records = tax._parse_main_table(tax.TEX.read_text(encoding="utf-8").splitlines())
    by_id = {r["id"]: r for r in records}
    subdomain_titles = {r["subdomain"]: r["subdomain_title"] for r in records}
    return by_id, subdomain_titles


_DEFAULT_NEW_SUBCONTROL_TIER = 3
_DEFAULT_PARENT_TIER = 2


def build_records() -> list[dict[str, Any]]:
    ecc = parse_ecc_english()
    valid_ids = {r["id"] for r in ecc}
    arabic = parse_ecc_arabic(valid_ids)
    gecc_arabic = parse_gecc_arabic(valid_ids)
    tex_by_id, subdomain_titles = _tex_metadata()

    child_tiers: dict[str, list[int]] = {}
    for r in ecc:
        if r["kind"] == "sub":
            parent = r["id"].rsplit("-", 1)[0]
            meta = tex_by_id.get(r["id"])
            if meta:
                child_tiers.setdefault(parent, []).append(meta["tier"])

    out: list[dict[str, Any]] = []
    for r in ecc:
        cid = r["id"]
        meta = tex_by_id.get(cid)
        record: dict[str, Any] = {
            "id": cid,
            "kind": r["kind"],
            "domain": r["domain"],
            "domain_title": r["domain_title"],
            "subdomain": r["subdomain"],
            "subdomain_title": subdomain_titles.get(r["subdomain"], r["subdomain"]),
            "clause_en": r["text_en"],
            "clause_en_source": "nca-pdf-en",
            "clause_ar": arabic.get(cid) or gecc_arabic.get(cid, ""),
            "clause_ar_source": (
                "nca-pdf" if cid in arabic else ("gecc-2026-guide" if cid in gecc_arabic else "")
            ),
        }
        if meta is not None:
            record.update(
                tier=meta["tier"],
                tier_source="taxonomy",
                method_en=meta["method_en"],
                reading_en=meta["reading_en"],
                remediation_en=meta["remediation_en"],
                ncnicc_class_a=meta["ncnicc_class_a"],
                ncnicc_class_b=meta["ncnicc_class_b"],
            )
        else:
            if r["kind"] == "main":
                tiers = child_tiers.get(cid)
                tier = min(tiers) if tiers else _DEFAULT_PARENT_TIER
            else:
                tier = _DEFAULT_NEW_SUBCONTROL_TIER
            record.update(
                tier=tier,
                tier_source="default-pending-expert",
                method_en="",
                reading_en="",
                remediation_en="",
                ncnicc_class_a=None,
                ncnicc_class_b=None,
            )
        out.append(record)
    return out


def main() -> None:
    import extract_taxonomy as tax

    records = build_records()
    ncnicc = tax._parse_ncnicc_exclusive(tax.TEX.read_text(encoding="utf-8").splitlines())
    ncnicc_ar = parse_ncnicc_arabic({r["id"] for r in ncnicc})
    for r in ncnicc:
        r["clause_ar"] = ncnicc_ar.get(r["id"], "")
        r["clause_ar_source"] = "ncnicc-md" if r["id"] in ncnicc_ar else ""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "ecc_records.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (OUT_DIR / "ncnicc_exclusive.json").write_text(
        json.dumps(ncnicc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    main_ct = sum(1 for r in records if r["kind"] == "main")
    sub_ct = sum(1 for r in records if r["kind"] == "sub")
    tier1 = sum(1 for r in records if r["tier"] == 1)
    ar = sum(1 for r in records if r["clause_ar"])
    ar_nca = sum(1 for r in records if r["clause_ar_source"] == "nca-pdf")
    ar_gecc = sum(1 for r in records if r["clause_ar_source"] == "gecc-2026-guide")
    taxonomy = sum(1 for r in records if r["tier_source"] == "taxonomy")
    print(f"wrote ecc_records.json: {main_ct} main + {sub_ct} sub = {len(records)}")
    print(f"  Tier-1: {tier1} | taxonomy-classified: {taxonomy} | new: {len(records) - taxonomy}")
    print(
        f"  authoritative Arabic: {ar} (nca-pdf {ar_nca} + gecc-guide {ar_gecc}) "
        f"| subdomains: {len({r['subdomain'] for r in records})}"
    )


if __name__ == "__main__":
    main()
