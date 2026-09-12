from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

from extract_regulations import parse_gecc_arabic, parse_ncnicc_arabic

_GECC_MD = """
**5-3-4-2** — نص تجريبي أول يذكر SPF وDKIM وDMARC لغرض الاختبار فقط.

**إرشادات تطبيق الضوابط:**
- بند إرشادي لا يجب التقاطه كضابط.

**1-3-10-1** — عبارة تجريبية ثانية لضابط المجال العاشر لغرض الاختبار.

**9-9-9-9** — ضابط غير موجود يجب رفضه.
"""


def test_gecc_parser_de_reverses_and_captures_statement() -> None:
    out = parse_gecc_arabic({"2-4-3-5", "1-10-3-1"}, md_text=_GECC_MD)
    assert set(out) == {"2-4-3-5", "1-10-3-1"}
    assert "SPF" in out["2-4-3-5"] and out["2-4-3-5"].startswith("نص تجريبي")
    assert out["1-10-3-1"].startswith("عبارة تجريبية")
    assert "بند إرشادي" not in out["2-4-3-5"]


def test_gecc_parser_rejects_ids_not_in_the_catalog() -> None:
    out = parse_gecc_arabic({"2-4-3-5", "1-10-3-1"}, md_text=_GECC_MD)
    assert "9-9-9-9" not in out


def test_gecc_parser_first_occurrence_wins() -> None:
    md = (
        "**5-3-4-2** — النص العربي الأول لهذا الضابط وهو نص كافٍ الطول.\n\n"
        "**5-3-4-2** — النص العربي الثاني المختلف تماماً عن الأول.\n"
    )
    out = parse_gecc_arabic({"2-4-3-5"}, md_text=md)
    assert out["2-4-3-5"].startswith("النص العربي الأول")


def test_ncnicc_parser_reads_reversed_table_ids() -> None:
    md = (
        "| 2-1-7-2 | جملة تجريبية أولى في جدول الاختبار. | ملزم | موصى به |\n"
        "| 3-1-7-2 | جملة تجريبية ثانية في جدول الاختبار. | ملزم | ملزم |\n"
    )
    out = parse_ncnicc_arabic({"2-7-1-2", "2-7-1-3"}, md_text=md)
    assert out["2-7-1-2"].startswith("جملة تجريبية أولى")
    assert out["2-7-1-3"].startswith("جملة تجريبية ثانية")
