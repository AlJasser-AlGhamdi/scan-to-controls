from __future__ import annotations

from datetime import UTC, datetime

from p2c.discovery.merge import merge_assets
from p2c.discovery.normalize import assets_from_hosts
from p2c.schemas.enums import DiscoveryMethod
from p2c.schemas.models import Asset

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _src(hosts: list[str], tool: str, method: DiscoveryMethod, version: str) -> list[Asset]:
    return assets_from_hosts(
        hosts,
        apex="example.com",
        source_tool=tool,
        tool_version=version,
        method=method,
        consent_ref="C1",
        now=NOW,
    )


def test_merge_dedupes_and_records_all_sources() -> None:
    subfinder = _src(
        ["www.example.com", "api.example.com"], "subfinder", DiscoveryMethod.SUBFINDER, "v2.14.0"
    )
    crtsh = _src(["www.example.com", "mail.example.com"], "crt.sh", DiscoveryMethod.CRTSH, "crt.sh-json")

    merged = merge_assets(subfinder + crtsh)

    assert [a.value for a in merged] == ["api.example.com", "mail.example.com", "www.example.com"]
    for asset in merged:
        assert asset.attributes["discovered_by"]
    corroborated = next(a for a in merged if a.value == "www.example.com")
    sources = {d["source_tool"] for d in corroborated.attributes["discovered_by"]}
    assert sources == {"subfinder", "crt.sh"}


def test_merge_preserves_source_attributes() -> None:
    amass = assets_from_hosts(
        ["vpn.example.com"],
        apex="example.com",
        source_tool="amass-passive",
        tool_version="v5.1.1",
        method=DiscoveryMethod.AMASS_PASSIVE,
        consent_ref="C1",
        now=NOW,
        attributes_for={"vpn.example.com": {"addresses": ["203.0.113.5"]}},
    )
    merged = merge_assets(amass)
    assert merged[0].attributes["addresses"] == ["203.0.113.5"]
    assert merged[0].attributes["discovered_by"][0]["source_tool"] == "amass-passive"


def test_merge_is_deterministic_regardless_of_input_order() -> None:
    a = _src(["www.example.com"], "subfinder", DiscoveryMethod.SUBFINDER, "v2.14.0")
    b = _src(["www.example.com"], "crt.sh", DiscoveryMethod.CRTSH, "crt.sh-json")
    assert [x.model_dump() for x in merge_assets(a + b)] == [x.model_dump() for x in merge_assets(b + a)]
