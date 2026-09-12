from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
PRIVATE_CATALOG_DIR = ROOT / "private" / "catalogs"
PUBLIC_CATALOG_DIR = ROOT / "taxonomy"


def _resolve_catalog_dir() -> Path:
    override = os.environ.get("P2C_CATALOG_DIR")
    if override:
        return Path(override)
    if (PRIVATE_CATALOG_DIR / "ecc-2-2024.json").is_file():
        return PRIVATE_CATALOG_DIR
    return PUBLIC_CATALOG_DIR


CATALOG_DIR = _resolve_catalog_dir()
SOURCE_DIR = CATALOG_DIR / "_source"
ECC_CATALOG = CATALOG_DIR / "ecc-2-2024.json"
NCNICC_CATALOG = CATALOG_DIR / "ncnicc-1-2025.json"
CROSSWALK = CATALOG_DIR / "crosswalk.json"

ATLAS_NS = "https://atlas.sa/ns/oscal"
CATALOG_VERSION = "2024.1"
OSCAL_VERSION = "1.1.2"
CATALOG_LAST_MODIFIED = "2026-01-01T00:00:00+00:00"

NATIVE_ID_RE = re.compile(r"^\d{1,2}-\d{1,2}-\d{1,2}(-\d{1,2})?$")
_PREFIXES = {"ecc": "ecc-", "ncnicc": "ncnicc-"}
_SUBCONTROL_HYPHENS = 3


def native_to_oscal(native: str, framework: str) -> str:
    return f"{_PREFIXES[framework]}{native}"


def oscal_to_native(oscal_id: str) -> str:
    for prefix in _PREFIXES.values():
        if oscal_id.startswith(prefix):
            return oscal_id[len(prefix) :]
    return oscal_id


def is_valid_native_id(value: str) -> bool:
    return bool(NATIVE_ID_RE.match(value))


@dataclass(frozen=True)
class ControlEntry:

    native_id: str
    oscal_id: str
    framework: str
    title: str
    tier: int
    domain: str
    subdomain: str
    kind: str
    statement_en: str
    statement_ar: str | None
    assessment_en: str
    remediation_en: str
    ncnicc_class_a: str | None = None
    ncnicc_class_b: str | None = None
    ncnicc_class_a_status: str | None = None
    ncnicc_class_b_status: str | None = None

    @property
    def is_subcontrol(self) -> bool:
        return self.native_id.count("-") == _SUBCONTROL_HYPHENS


def _prop_map(props: list[dict[str, Any]] | None) -> dict[str, str]:
    return {p["name"]: p["value"] for p in (props or [])}


def _part_texts(parts: list[dict[str, Any]] | None) -> dict[tuple[str, str | None], str]:
    out: dict[tuple[str, str | None], str] = {}
    for part in parts or []:
        out[(part.get("name", ""), part.get("class"))] = part.get("prose", "")
    return out


def _entry_from_control(control: dict[str, Any], framework: str) -> ControlEntry:
    props = _prop_map(control.get("props"))
    texts = _part_texts(control.get("parts"))
    native = props.get("label", oscal_to_native(control["id"]))
    return ControlEntry(
        native_id=native,
        oscal_id=control["id"],
        framework=framework,
        title=control.get("title", ""),
        tier=int(props.get("tier", "0")),
        domain=props.get("domain", native.split("-", 1)[0]),
        subdomain=props.get("subdomain", "-".join(native.split("-")[:2])),
        kind=props.get("kind", ""),
        statement_en=texts.get(("statement", "en"), ""),
        statement_ar=texts.get(("statement", "ar")),
        assessment_en=texts.get(("assessment-method", None), ""),
        remediation_en=texts.get(("remediation", None), ""),
        ncnicc_class_a=props.get("ncnicc-class-a"),
        ncnicc_class_b=props.get("ncnicc-class-b"),
        ncnicc_class_a_status=props.get("ncnicc-class-a-status"),
        ncnicc_class_b_status=props.get("ncnicc-class-b-status"),
    )


def _walk_controls(node: dict[str, Any], framework: str, out: list[ControlEntry]) -> None:
    for group in node.get("groups", []):
        _walk_controls(group, framework, out)
    for control in node.get("controls", []):
        out.append(_entry_from_control(control, framework))
        _walk_controls(control, framework, out)


@dataclass
class CatalogIndex:

    entries: dict[str, ControlEntry] = field(default_factory=dict)

    @classmethod
    def from_files(cls, *paths: Path) -> CatalogIndex:
        entries: dict[str, ControlEntry] = {}
        for path in paths:
            doc = json.loads(path.read_text(encoding="utf-8"))
            catalog = doc["catalog"]
            framework = "ncnicc" if "ncnicc" in path.name else "ecc"
            collected: list[ControlEntry] = []
            _walk_controls(catalog, framework, collected)
            for entry in collected:
                if entry.native_id in entries:
                    raise ValueError(f"duplicate control id in catalog: {entry.native_id}")
                entries[entry.native_id] = entry
        return cls(entries=entries)

    def ids(self) -> frozenset[str]:
        return frozenset(self.entries)

    def is_valid(self, native_id: str) -> bool:
        return native_id in self.entries

    def get(self, native_id: str) -> ControlEntry | None:
        return self.entries.get(native_id)

    def require(self, native_id: str) -> ControlEntry:
        entry = self.entries.get(native_id)
        if entry is None:
            raise KeyError(f"unknown control id: {native_id!r}")
        return entry

    def by_tier(self, tier: int) -> list[ControlEntry]:
        return [e for e in self.entries.values() if e.tier == tier]

    def main_controls(self) -> list[ControlEntry]:
        return [e for e in self.entries.values() if e.framework == "ecc" and not e.is_subcontrol]

    def subcontrols(self) -> list[ControlEntry]:
        return [e for e in self.entries.values() if e.framework == "ecc" and e.is_subcontrol]

    def subdomains(self) -> frozenset[str]:
        return frozenset(e.subdomain for e in self.entries.values() if e.framework == "ecc")


@lru_cache(maxsize=1)
def load_default_index() -> CatalogIndex:
    return CatalogIndex.from_files(ECC_CATALOG, NCNICC_CATALOG)
