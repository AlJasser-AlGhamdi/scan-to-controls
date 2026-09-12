from __future__ import annotations

from pathlib import Path

import pytest

from p2c.mapping.catalog import ECC_CATALOG, NCNICC_CATALOG, SOURCE_DIR
from p2c.mapping.catalog_build import build_all

pytestmark = pytest.mark.skipif(
    not SOURCE_DIR.is_dir(), reason="private catalog source records absent (stripped public tree)"
)


def _build_into(tmp_dir: Path) -> tuple[Path, Path]:
    tmp_dir.mkdir(parents=True, exist_ok=True)
    return build_all(
        source_dir=SOURCE_DIR,
        ecc_out=tmp_dir / "ecc-2-2024.json",
        ncnicc_out=tmp_dir / "ncnicc-1-2025.json",
    )


def test_rebuild_matches_committed_catalogs(tmp_path: Path) -> None:
    ecc_out, ncnicc_out = _build_into(tmp_path)
    assert ecc_out.read_text(encoding="utf-8") == ECC_CATALOG.read_text(encoding="utf-8")
    assert ncnicc_out.read_text(encoding="utf-8") == NCNICC_CATALOG.read_text(encoding="utf-8")


def test_rebuild_is_byte_identical_twice(tmp_path: Path) -> None:
    first, _ = _build_into(tmp_path / "a")
    second, _ = _build_into(tmp_path / "b")
    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")
