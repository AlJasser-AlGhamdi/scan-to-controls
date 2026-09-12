from __future__ import annotations
import json
from collections import defaultdict
from pathlib import Path

from p2c.mapping.catalog import CATALOG_DIR
from p2c.mapping.rules import RULES

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "taxonomy" / "release" / "sort_overlay.json"
CATALOGS = [CATALOG_DIR / "ecc-2-2024.json", CATALOG_DIR / "ncnicc-1-2025.json"]


def _walk(control: dict, out: list[dict]) -> None:
    props = {p["name"]: p["value"] for p in control.get("props", [])}
    if "tier" in props:
        out.append({"label": control.get("id", "").removeprefix("ecc-").removeprefix("ncnicc-"), "props": props})
    for child in control.get("controls", []):
        _walk(child, out)


def _all_props() -> list[dict]:
    found: list[dict] = []
    for path in CATALOGS:
        cat = json.loads(path.read_text(encoding="utf-8"))["catalog"]
        for group in cat.get("groups", []):
            for sub in group.get("groups", []):
                for control in sub.get("controls", []):
                    _walk(control, found)
            for control in group.get("controls", []):
                _walk(control, found)
    return found


def main() -> None:
    checks_for: dict[str, list[str]] = defaultdict(list)
    for rule in RULES.values():
        for cid in rule.control_ids:
            checks_for[cid].append(str(rule.check_id))
    for cid in checks_for:
        checks_for[cid] = sorted(set(checks_for[cid]))

    rows = []
    for entry in _all_props():
        props = entry["props"]
        cid = props.get("label") or entry["label"]
        tier = props["tier"]
        rows.append(
            {
                "id": cid,
                "kind": props.get("kind"),
                "domain": props.get("domain"),
                "subdomain": props.get("subdomain"),
                "tier": int(tier),
                "tier_class": {"1": "scan-provable", "2": "internal-assessment", "3": "declaration"}[tier],
                "tier_source": props.get("tier-source"),
                "ncnicc_class_a_status": props.get("ncnicc-class-a-status"),
                "ncnicc_class_b_status": props.get("ncnicc-class-b-status"),
                "scanner_checks": checks_for.get(cid, []),
            }
        )
    rows.sort(key=lambda r: [int(x) for x in r["id"].split("-")])

    tier_counts: dict[str, int] = defaultdict(int)
    for r in rows:
        tier_counts[r["tier_class"]] += 1
    scan_provable = tier_counts["scan-provable"]

    payload = {
        "schema": "p2c-sort-overlay/1",
        "description": (
            "ID-keyed sort of ECC-2:2024 and NCNICC-1:2025 controls into scan-provable "
            "(Tier 1), internal-assessment (Tier 2), and declaration (Tier 3). Contains no "
            "NCA control text; control text is NCA copyright and is not redistributable. "
            "Resolve identifiers against the official NCA publications at nca.gov.sa."
        ),
        "counts": {
            "total_rows": len(rows),
            "scan_provable": scan_provable,
            "internal_assessment": tier_counts["internal-assessment"],
            "declaration": tier_counts["declaration"],
            "scan_provable_share": round(scan_provable / len(rows), 4),
        },
        "controls": rows,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(rows)} rows, counts={dict(payload['counts'])}")


if __name__ == "__main__":
    main()
