from __future__ import annotations

from p2c.mapping.catalog import load_default_index
from p2c.mapping.models import MappingMethod
from p2c.mapping.rules import RULES, MappingEngine, check_id_from_finding, validate_rules
from p2c.scanning.catalog import CheckId, build_finding
from p2c.schemas.enums import EvidenceTier, Severity
from p2c.schemas.models import Finding


def _finding(check: CheckId, asset: str = "example.com"):
    return build_finding(
        check,
        asset=asset,
        observed_state=f"{check.value} on {asset}",
        consent_ref="C1",
        source_tool="atlas-scan",
        tool_version="0.0.0",
    )


GOLDEN: dict[CheckId, list[str]] = {
    CheckId.MISSING_HSTS: ["2-15-3-3", "2-8-3-3"],
    CheckId.MISSING_CSP: ["2-15-3-3"],
    CheckId.NO_HTTPS_REDIRECT: ["2-15-3-3"],
    CheckId.LEGACY_TLS_VERSION: ["2-8-3-3"],
    CheckId.WEAK_TLS_CIPHER: ["2-8-3-3"],
    CheckId.EXPIRED_CERTIFICATE: ["2-8-3-3"],
    CheckId.WAF_ABSENT: ["2-15-3-1"],
    CheckId.EXPOSED_INTERNAL_PORT: ["2-5-3-1"],
    CheckId.EXPOSED_MANAGEMENT_PORT: ["2-2-3-2", "2-2-3-1"],
    CheckId.HIGH_RISK_PORT_OPEN: ["2-5-3-5"],
    CheckId.OUTDATED_EXPOSED_SOFTWARE: ["2-10-3-4", "2-10-3-1"],
    CheckId.SPF_MISSING: ["2-4-3-5"],
    CheckId.DMARC_MISSING_OR_NONE: ["2-4-3-5"],
    CheckId.DKIM_MISSING: ["2-4-3-5"],
}


def test_golden_mappings_are_stable() -> None:
    engine = MappingEngine()
    for check, expected in GOLDEN.items():
        mappings = engine.map_finding(_finding(check))
        assert [m.control_id for m in mappings] == expected, check


def test_all_rules_map_to_catalog_controls() -> None:
    validate_rules(load_default_index())


def test_every_rule_is_covered_by_a_finding() -> None:
    engine = MappingEngine()
    for check in RULES:
        mappings = engine.map_finding(_finding(check))
        assert mappings, f"rule for {check} produced no mapping"
        assert all(m.method is MappingMethod.DETERMINISTIC for m in mappings)
        assert all(m.confidence == 1.0 for m in mappings)


def test_mappings_carry_tier_and_crosswalk() -> None:
    engine = MappingEngine()
    (spf,) = engine.map_finding(_finding(CheckId.SPF_MISSING))
    assert spf.control_id == "2-4-3-5"
    assert spf.tier == 1
    assert spf.ncnicc_class_a == "4-2"
    assert spf.rule_id == "MR-spf_missing"
    assert spf.rationale


def test_check_id_recovered_from_finding_id() -> None:
    assert check_id_from_finding(_finding(CheckId.SPF_MISSING)) is CheckId.SPF_MISSING


def test_map_findings_is_sorted_deterministic() -> None:
    engine = MappingEngine()
    findings = [_finding(CheckId.SPF_MISSING, "b.example"), _finding(CheckId.MISSING_HSTS, "a.example")]
    out = engine.map_findings(findings)
    keys = [(m.control_id, m.asset) for m in out]
    assert keys == sorted(keys)


def _raw_finding(finding_id: str, control_ids: list[str]) -> Finding:
    return Finding(
        finding_id=finding_id,
        asset="example.com",
        source_tool="nuclei",
        tool_version="v3",
        observed_state="some finding",
        severity=Severity.HIGH,
        control_ids=control_ids,
        evidence_tier=EvidenceTier.TIER_1,
        consent_ref="C1",
    )


def test_finding_with_noncatalog_control_id_is_dropped() -> None:
    finding = _raw_finding("cve-template:example.com", ["9-9-9-9", "2-8-3-3"])
    ids = [m.control_id for m in MappingEngine().map_finding(finding)]
    assert ids == ["2-8-3-3"]


def test_duplicate_control_ids_are_deduplicated() -> None:
    finding = _raw_finding("nuclei:example.com", ["2-8-3-3", "2-8-3-3", "2-4-3-5"])
    ids = [m.control_id for m in MappingEngine().map_finding(finding)]
    assert ids == ["2-8-3-3", "2-4-3-5"]


def test_rule_and_finding_tags_are_unioned_losslessly() -> None:
    finding = _raw_finding("spf_missing:example.com", ["2-4-3-5", "2-8-3-3"])
    mappings = {m.control_id: m for m in MappingEngine().map_finding(finding)}
    assert set(mappings) == {"2-4-3-5", "2-8-3-3"}
    assert mappings["2-4-3-5"].rule_id == "MR-spf_missing"
    assert mappings["2-8-3-3"].rule_id is None
    assert mappings["2-8-3-3"].rationale == "catalog-tagged finding"


def test_mappings_carry_ncnicc_status() -> None:
    (spf,) = MappingEngine().map_finding(_finding(CheckId.SPF_MISSING))
    assert spf.ncnicc_class_a == "4-2"
    assert spf.ncnicc_class_a_status == "M"
    assert spf.ncnicc_class_b_status == "M"
