from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from trestle.oscal.catalog import Catalog, Control, Group1, Group2
from trestle.oscal.common import Metadata, Part, Property

from p2c.mapping import _arabic
from p2c.mapping.catalog import (
    ATLAS_NS,
    CATALOG_LAST_MODIFIED,
    CATALOG_VERSION,
    ECC_CATALOG,
    NCNICC_CATALOG,
    OSCAL_VERSION,
    SOURCE_DIR,
    native_to_oscal,
)

DOMAIN_ORDER = ("1", "2", "3", "4")
_UUID_NS = uuid.UUID("00000000-a71a-5000-8000-000000000000")


def _det_uuid(name: str) -> str:
    return str(uuid.uuid5(_UUID_NS, name))


def _prop(name: str, value: str, *, ns: bool = True) -> Property:
    return Property(name=name, value=value, ns=ATLAS_NS if ns else None)


def _statement_parts(record: dict[str, Any]) -> tuple[list[Part], str]:
    parts = [Part(name="statement", class_="en", prose=record["clause_en"])]
    pdf_ar = record.get("clause_ar")
    if pdf_ar:
        ar_source = record.get("clause_ar_source") or "nca-pdf"
        parts.append(
            Part(name="statement", class_="ar", prose=pdf_ar, props=[_prop("translation-status", ar_source)])
        )
        return parts, ar_source
    prose_ar, status = _arabic.arabic_clause(record["id"], record["subdomain"], record["clause_en"])
    if status != "pending":
        parts.append(
            Part(name="statement", class_="ar", prose=prose_ar, props=[_prop("translation-status", status)])
        )
    return parts, status


def _ncnicc_props(record: dict[str, Any]) -> list[Property]:
    props: list[Property] = []
    for cls, key in (("a", "ncnicc_class_a"), ("b", "ncnicc_class_b")):
        mapping = record.get(key)
        if mapping:
            props.append(_prop(f"ncnicc-class-{cls}", mapping["subcomponent"]))
            props.append(_prop(f"ncnicc-class-{cls}-status", mapping["status"]))
    return props


def _control(record: dict[str, Any], children: list[Control] | None = None) -> Control:
    cid = record["id"]
    parts, ar_status = _statement_parts(record)
    if record.get("reading_en"):
        parts.append(Part(name="guidance", class_="en", prose=record["reading_en"]))
    if record.get("method_en"):
        parts.append(Part(name="assessment-method", ns=ATLAS_NS, prose=record["method_en"]))
    if record.get("remediation_en"):
        parts.append(Part(name="remediation", ns=ATLAS_NS, prose=record["remediation_en"]))
    props = [
        _prop("label", cid, ns=False),
        _prop("tier", str(record["tier"])),
        _prop("tier-source", record.get("tier_source", "taxonomy")),
        _prop("domain", record["domain"]),
        _prop("subdomain", record["subdomain"]),
        _prop("kind", record["kind"]),
        _prop("translation-status", ar_status),
        _prop("text-source", record.get("clause_en_source", "nca-pdf-en")),
        *_ncnicc_props(record),
    ]
    return Control(
        id=native_to_oscal(cid, "ecc"),
        title=_title(record["clause_en"]),
        props=props,
        parts=parts,
        controls=children or None,
    )


_MAX_TITLE = 158


def _title(clause_en: str) -> str:
    first = clause_en.partition(". ")[0].strip()
    return (first[: _MAX_TITLE - 1] + "…") if len(first) > _MAX_TITLE else first


_SUBDOMAIN_TITLES: dict[str, str] = {}


def _subdomain_title(subdomain: str) -> str:
    return _SUBDOMAIN_TITLES.get(subdomain, subdomain)


def _build_ecc(records: list[dict[str, Any]]) -> Catalog:
    for r in records:
        _SUBDOMAIN_TITLES.setdefault(r["subdomain"], r["subdomain_title"])

    by_subdomain: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        by_subdomain.setdefault(r["subdomain"], []).append(r)

    domain_groups: list[Group1] = []
    for domain in DOMAIN_ORDER:
        subdomain_groups: list[Group2] = []
        subs = sorted(
            (s for s in by_subdomain if s.split("-")[0] == domain),
            key=lambda s: int(s.split("-")[1]),
        )
        for sub in subs:
            controls = _subdomain_controls(by_subdomain[sub])
            subdomain_groups.append(
                Group2(
                    id=f"ecc-sd-{sub}",
                    title=_subdomain_title(sub),
                    props=[_prop("label", sub, ns=False), _prop("title-ar", _arabic.SUBDOMAIN_AR[sub])],
                    controls=controls,
                )
            )
        domain_groups.append(
            Group1(
                id=f"ecc-d{domain}",
                title=_domain_title(domain),
                props=[_prop("label", domain, ns=False), _prop("title-ar", _arabic.DOMAIN_AR[domain])],
                groups=subdomain_groups,
            )
        )
    metadata = _metadata("ATLAS OSCAL Catalog — ECC-2:2024", records)
    return Catalog(uuid=_det_uuid("ecc-2-2024"), metadata=metadata, groups=domain_groups)


_DOMAIN_TITLES = {
    "1": "Cybersecurity Governance",
    "2": "Cybersecurity Defense",
    "3": "Cybersecurity Resilience",
    "4": "Third-Party and Cloud Computing Cybersecurity",
}


def _domain_title(domain: str) -> str:
    return _DOMAIN_TITLES[domain]


def _subdomain_controls(records: list[dict[str, Any]]) -> list[Control]:
    mains = _sorted_by_id([r for r in records if r["kind"] == "main"])
    children: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        if r["kind"] == "sub":
            children.setdefault(r["id"].rsplit("-", 1)[0], []).append(r)

    controls: list[Control] = []
    for main in mains:
        kids = [_control(k) for k in _sorted_by_id(children.get(main["id"], []))]
        controls.append(_control(main, children=kids))
    return controls


def _sorted_by_id(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(records, key=lambda r: _id_key(r["id"]))


def _sorted_controls(controls: list[Control]) -> list[Control]:
    return sorted(controls, key=lambda c: _id_key(_label(c)))


def _label(control: Control) -> str:
    for p in control.props or []:
        if p.name == "label":
            return p.value
    return control.id


def _id_key(native: str) -> tuple[int, ...]:
    return tuple(int(x) for x in native.split("-"))


def _metadata(title: str, records: list[dict[str, Any]]) -> Metadata:
    subcontrols = sum(1 for r in records if r["kind"] == "sub")
    arabic_nca = sum(1 for r in records if r.get("clause_ar_source") == "nca-pdf")
    arabic_gecc = sum(1 for r in records if r.get("clause_ar_source") == "gecc-2026-guide")
    arabic_hand = sum(1 for r in records if not r.get("clause_ar") and r["id"] in _arabic.CLAUSE_AR)
    props = [
        _prop("main-controls", str(sum(1 for r in records if r["kind"] == "main"))),
        _prop("subcontrols-encoded", str(subcontrols)),
        _prop("subcontrols-official", "92"),
        _prop("arabic-nca-pdf", str(arabic_nca)),
        _prop("arabic-gecc-guide", str(arabic_gecc)),
        _prop("arabic-hand-translated", str(arabic_hand)),
        _prop(
            "source", "NCA ECC-2:2024 PDF + NCA Guide-to-ECC + spec/atlas_taxonomy_v4.tex (ATLAS metadata)"
        ),
    ]
    return Metadata(
        title=title,
        last_modified=CATALOG_LAST_MODIFIED,
        version=CATALOG_VERSION,
        oscal_version=OSCAL_VERSION,
        props=props,
    )


def _build_ncnicc(records: list[dict[str, Any]]) -> Catalog:
    controls: list[Control] = []
    for r in records:
        cid = r["id"]
        parts = [Part(name="statement", class_="en", prose=r["clause_en"])]
        record_ar = r.get("clause_ar")
        if record_ar:
            ar_source = r.get("clause_ar_source") or "ncnicc-md"
            parts.append(
                Part(
                    name="statement",
                    class_="ar",
                    prose=record_ar,
                    props=[_prop("translation-status", ar_source)],
                )
            )
        else:
            prose_ar, status = _arabic.arabic_clause(cid, "", r["clause_en"])
            if status != "pending":
                parts.append(
                    Part(
                        name="statement",
                        class_="ar",
                        prose=prose_ar,
                        props=[_prop("translation-status", status)],
                    )
                )
        parts.append(Part(name="guidance", class_="en", prose=r["reading_en"]))
        parts.append(Part(name="assessment-method", ns=ATLAS_NS, prose=r["method_en"]))
        parts.append(Part(name="remediation", ns=ATLAS_NS, prose=r["remediation_en"]))
        props = [
            _prop("label", cid, ns=False),
            _prop("tier", str(r["tier"])),
            _prop("ncnicc-class-a-status", r["class_a"]),
            _prop("ncnicc-class-b-status", r["class_b"]),
            _prop("kind", "ncnicc_exclusive"),
            _prop("text-source", r.get("clause_en_source", "atlas-taxonomy-summary")),
        ]
        controls.append(
            Control(id=native_to_oscal(cid, "ncnicc"), title=r["clause_en"][:80], props=props, parts=parts)
        )
    metadata = Metadata(
        title="ATLAS OSCAL Catalog — NCNICC-1:2025 (exclusive controls)",
        last_modified=CATALOG_LAST_MODIFIED,
        version=CATALOG_VERSION,
        oscal_version=OSCAL_VERSION,
        props=[_prop("exclusive-controls", str(len(records))), _prop("source", "spec/atlas_taxonomy_v4.tex")],
    )
    group = Group2(
        id="ncnicc-exclusive",
        title="NCNICC-1:2025 controls with no ECC-2:2024 equivalent",
        controls=_sorted_controls(controls),
    )
    return Catalog(uuid=_det_uuid("ncnicc-1-2025"), metadata=metadata, groups=[group])


def build_all(
    *,
    source_dir: Path = SOURCE_DIR,
    ecc_out: Path = ECC_CATALOG,
    ncnicc_out: Path = NCNICC_CATALOG,
) -> tuple[Path, Path]:
    ecc_records = json.loads((source_dir / "ecc_records.json").read_text(encoding="utf-8"))
    ncnicc_records = json.loads((source_dir / "ncnicc_exclusive.json").read_text(encoding="utf-8"))
    ecc = _build_ecc(ecc_records)
    ncnicc = _build_ncnicc(ncnicc_records)
    ecc_out.parent.mkdir(parents=True, exist_ok=True)
    ecc.oscal_write(ecc_out)
    ncnicc.oscal_write(ncnicc_out)
    return ecc_out, ncnicc_out
