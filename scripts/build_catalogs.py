#!/usr/bin/env python3
from __future__ import annotations

from p2c.mapping.catalog import CatalogIndex, load_default_index
from p2c.mapping.catalog_build import build_all
from p2c.mapping.crosswalk import build_crosswalk, write_crosswalk


def main() -> None:
    ecc_path, ncnicc_path = build_all()
    load_default_index.cache_clear()
    index = CatalogIndex.from_files(ecc_path, ncnicc_path)
    mains = index.main_controls()
    subs = index.subcontrols()
    ncnicc_count = len([e for e in index.entries.values() if e.framework == "ncnicc"])
    print(f"wrote {ecc_path.name}: {len(mains)} main + {len(subs)} subcontrols")
    print(f"wrote {ncnicc_path.name}: {ncnicc_count} controls")
    print(f"subdomains: {len(index.subdomains())}   total control ids: {len(index.ids())}")

    crosswalk_path = write_crosswalk(index)
    entries = build_crosswalk(index)
    mapped = sum(1 for e in entries if not e.ncnicc_exclusive)
    exclusive = sum(1 for e in entries if e.ncnicc_exclusive)
    print(f"wrote {crosswalk_path.name}: {mapped} ECC↔NCNICC + {exclusive} NCNICC-exclusive")


if __name__ == "__main__":
    main()
