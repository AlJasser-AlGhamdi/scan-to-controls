from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field

from p2c.mapping.catalog import CROSSWALK, CatalogIndex, load_default_index
from p2c.schemas.models import AtlasModel


class CrosswalkEntry(AtlasModel):

    ecc_control_id: str | None = Field(default=None, description="None for NCNICC-exclusive controls")
    ncnicc_subcomponent: str = Field(description="e.g. 5-2, or the exclusive id 2-7-1-2")
    class_a_status: str = Field(description="M | R")
    class_b_status: str = Field(description="M | R")
    ncnicc_exclusive: bool = False


def build_crosswalk(index: CatalogIndex) -> list[CrosswalkEntry]:
    entries: list[CrosswalkEntry] = []
    for entry in index.entries.values():
        if entry.framework == "ecc" and entry.ncnicc_class_a:
            entries.append(
                CrosswalkEntry(
                    ecc_control_id=entry.native_id,
                    ncnicc_subcomponent=entry.ncnicc_class_a,
                    class_a_status=entry.ncnicc_class_a_status or "M",
                    class_b_status=entry.ncnicc_class_b_status or "R",
                )
            )
        elif entry.framework == "ncnicc":
            entries.append(
                CrosswalkEntry(
                    ecc_control_id=None,
                    ncnicc_subcomponent=entry.native_id,
                    class_a_status=entry.ncnicc_class_a_status or "M",
                    class_b_status=entry.ncnicc_class_b_status or "R",
                    ncnicc_exclusive=True,
                )
            )
    entries.sort(key=lambda e: (e.ncnicc_exclusive, e.ecc_control_id or e.ncnicc_subcomponent))
    return entries


def write_crosswalk(index: CatalogIndex, path: Path = CROSSWALK) -> Path:
    entries = build_crosswalk(index)
    payload = {
        "metadata": {
            "title": "ATLAS ECC-2:2024 ↔ NCNICC-1:2025 crosswalk",
            "mapped_ecc_controls": sum(1 for e in entries if not e.ncnicc_exclusive),
            "ncnicc_exclusive": sum(1 for e in entries if e.ncnicc_exclusive),
        },
        "entries": [e.model_dump() for e in entries],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


class Crosswalk:

    def __init__(self, entries: list[CrosswalkEntry]) -> None:
        self._entries = entries
        self._by_ecc = {e.ecc_control_id: e for e in entries if e.ecc_control_id is not None}

    @classmethod
    def load(cls, path: Path = CROSSWALK) -> Crosswalk:
        doc = json.loads(path.read_text(encoding="utf-8"))
        return cls([CrosswalkEntry.model_validate(e) for e in doc["entries"]])

    def ecc_to_ncnicc(self, ecc_control_id: str) -> CrosswalkEntry | None:
        return self._by_ecc.get(ecc_control_id)

    def exclusive_controls(self) -> list[CrosswalkEntry]:
        return [e for e in self._entries if e.ncnicc_exclusive]

    def entries(self) -> list[CrosswalkEntry]:
        return list(self._entries)


def load_default_crosswalk() -> Crosswalk:
    return Crosswalk.load()


def _build_default() -> list[CrosswalkEntry]:
    return build_crosswalk(load_default_index())
