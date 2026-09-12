from __future__ import annotations

from p2c.mapping.catalog import load_default_index
from p2c.mapping.crosswalk import Crosswalk, build_crosswalk


def test_three_ncnicc_exclusive_controls() -> None:
    cw = Crosswalk.load()
    exclusive = {e.ncnicc_subcomponent for e in cw.exclusive_controls()}
    assert exclusive == {"2-7-1-2", "2-12-1-2", "2-7-1-3"}


def test_exclusive_class_applicability() -> None:
    cw = Crosswalk.load()
    by_id = {e.ncnicc_subcomponent: e for e in cw.exclusive_controls()}
    assert by_id["2-7-1-3"].class_b_status == "M"
    assert by_id["2-7-1-2"].class_b_status == "R"
    assert by_id["2-12-1-2"].class_b_status == "R"
    assert all(e.class_a_status == "M" for e in cw.exclusive_controls())


def test_ecc_to_ncnicc_lookup() -> None:
    cw = Crosswalk.load()
    spf = cw.ecc_to_ncnicc("2-4-3-5")
    assert spf is not None
    assert spf.ncnicc_subcomponent == "4-2"
    assert spf.class_a_status == "M"


def test_privileged_access_is_recommended_for_class_b() -> None:
    cw = Crosswalk.load()
    pam = cw.ecc_to_ncnicc("2-2-3-4")
    assert pam is not None and pam.class_b_status == "R"


def test_crosswalk_derived_from_catalog_is_stable() -> None:
    entries = build_crosswalk(load_default_index())
    mapped = [e for e in entries if not e.ncnicc_exclusive]
    exclusive = [e for e in entries if e.ncnicc_exclusive]
    assert len(exclusive) == 3
    assert len(mapped) > 100
    assert all(e.ecc_control_id is not None for e in mapped)
