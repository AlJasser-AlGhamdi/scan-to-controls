from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from p2c._embed import normalize_text
from p2c.sovereignty.provenance import canonical_arabic, text_fingerprint

ROOT = Path(__file__).resolve().parents[2]


def _script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_normalisation_keeps_arabic_letters_and_drops_only_marks() -> None:
    assert normalize_text("هذا نصٌّ") == "هذا نص"
    assert normalize_text("تجريبـية") == "تجريبيه"


def test_a_faithful_copy_has_the_same_fingerprint_and_a_changed_word_does_not() -> None:
    official = "هذا نص تجريبي يكتبه الاختبار ليتحقق من البصمة."
    copied = "هذا  نصٌّ تجريبيٌّ\nيكتبه الاختبـارُ ليتحققَ من البصمةِ"
    assert text_fingerprint(copied) == text_fingerprint(official)
    assert text_fingerprint(official.replace("تجريبي", "حقيقي")) != text_fingerprint(official)
    assert canonical_arabic(official).split()[0] == "هذا"


def test_the_manifest_covers_every_row_and_carries_no_text() -> None:
    manifest = json.loads((ROOT / "taxonomy" / "release" / "text_manifest.json").read_text(encoding="utf-8"))
    overlay = json.loads((ROOT / "taxonomy" / "release" / "sort_overlay.json").read_text(encoding="utf-8"))
    assert {r["id"] for r in manifest["rows"]} == {c["id"] for c in overlay["controls"]}
    assert not any("\u0600" <= ch <= "\u06ff" for ch in json.dumps(manifest, ensure_ascii=False))


@pytest.mark.skipif(not (ROOT / "private" / "catalogs").exists(), reason="needs the private catalogues")
def test_our_own_text_verifies_on_every_row(tmp_path: Path) -> None:
    builder, verifier = _script("build_text_manifest"), _script("verify_against_nca")
    entries = {}
    for path in builder.CATALOGS:
        catalog = json.loads(path.read_text(encoding="utf-8"))

        def walk(node: object) -> None:
            if isinstance(node, dict):
                parts = node.get("parts") if "id" in node else None
                arabic = [p for p in parts or [] if isinstance(p, dict) and p.get("class") == "ar"]
                if arabic:
                    entries[str(node["id"]).split("-", 1)[1]] = " ".join(p["prose"] for p in arabic)
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(catalog)
    manifest = json.loads(verifier.MANIFEST.read_text(encoding="utf-8"))
    result = verifier.verify(entries, manifest)
    assert len(result["match"]) == 204 and not result["differ"] and not result["not_given"]
    first = next(iter(entries))
    changed = verifier.verify({first: entries[first] + " إضافة"}, manifest)
    assert changed["differ"] and changed["differ"][0].startswith(first)
