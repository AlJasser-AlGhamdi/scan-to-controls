from __future__ import annotations

from datetime import UTC, datetime

import pytest

from p2c.discovery.normalize import (
    assets_from_hosts,
    classify,
    in_scope_of,
    is_ip,
    is_valid_hostname,
    normalize_host,
    require_hostname,
    to_ascii,
    to_unicode,
)
from p2c.schemas.enums import AssetType, DiscoveryMethod

NOW = datetime(2026, 1, 1, tzinfo=UTC)

IDN_UNICODE = "مثال.السعودية"
IDN_ALABEL = "xn--mgbh0fb.xn--mgberp4a5d4ar"


def test_normalize_host_lowercase_dedot_dewildcard() -> None:
    assert normalize_host("WWW.Example.COM.") == "www.example.com"
    assert normalize_host("*.example.com") == "example.com"
    assert normalize_host("  API.example.com ") == "api.example.com"


def test_normalize_host_strips_all_wildcards_idempotently() -> None:
    assert normalize_host("*.*.example.com") == "example.com"
    once = normalize_host("*.*.example.com")
    assert normalize_host(once) == once


def test_normalize_host_rejects_internal_whitespace_and_controls() -> None:
    assert normalize_host("evil\nother.example.com") == ""
    assert normalize_host("a b.example.com") == ""
    assert normalize_host("bad\x00.example.com") == ""


def test_hostname_validation() -> None:
    assert is_valid_hostname("api.example.com")
    assert not is_valid_hostname("-flaginjection.com")
    assert not is_valid_hostname("example.com&issuer=x")
    assert not is_valid_hostname("no-tld")
    assert require_hostname("API.Example.com.") == "api.example.com"
    with pytest.raises(ValueError, match="invalid target"):
        require_hostname("-oJ /etc/passwd")


def test_idn_arabic_host_is_encoded_not_dropped() -> None:
    assert to_ascii(IDN_UNICODE) == IDN_ALABEL
    assert to_unicode(IDN_ALABEL) == IDN_UNICODE
    assert normalize_host(IDN_UNICODE) == IDN_ALABEL
    assert is_valid_hostname(IDN_UNICODE)
    assert require_hostname(IDN_UNICODE) == IDN_ALABEL
    assert in_scope_of("خدمة." + IDN_UNICODE, IDN_UNICODE)


def test_idn_asset_keeps_unicode_label() -> None:
    assets = assets_from_hosts(
        [IDN_UNICODE, "خدمة." + IDN_UNICODE],
        apex=IDN_UNICODE,
        source_tool="crt.sh",
        tool_version="crt.sh-json",
        method=DiscoveryMethod.CRTSH,
        consent_ref="C1",
        now=NOW,
    )
    apex_asset = next(a for a in assets if a.value == IDN_ALABEL)
    assert apex_asset.attributes["unicode_host"] == IDN_UNICODE
    assert to_unicode(apex_asset.value) == IDN_UNICODE


def test_is_ip() -> None:
    assert is_ip("93.184.216.34")
    assert is_ip("2001:db8::1")
    assert not is_ip("example.com")


def test_classify() -> None:
    assert classify("example.com", "example.com") is AssetType.DOMAIN
    assert classify("api.example.com", "example.com") is AssetType.SUBDOMAIN
    assert classify("93.184.216.34", "example.com") is AssetType.IP


def test_in_scope_of() -> None:
    assert in_scope_of("api.example.com", "example.com")
    assert in_scope_of("example.com", "example.com")
    assert not in_scope_of("evil.com", "example.com")
    assert not in_scope_of("notexample.com", "example.com")
    assert in_scope_of("10.0.0.1", "example.com")


def test_assets_from_hosts_filters_dedups_and_tags_provenance() -> None:
    assets = assets_from_hosts(
        ["www.example.com", "WWW.example.com.", "evil.com", "api.example.com", "*.example.com"],
        apex="example.com",
        source_tool="subfinder",
        tool_version="v2.14.0",
        method=DiscoveryMethod.SUBFINDER,
        consent_ref="C1",
        now=NOW,
    )
    values = [a.value for a in assets]
    assert values == ["api.example.com", "example.com", "www.example.com"]
    for asset in assets:
        assert asset.source_tool == "subfinder"
        assert asset.tool_version == "v2.14.0"
        assert asset.discovery_method == "subfinder"
        assert asset.consent_ref == "C1"
        assert asset.first_seen == NOW


def test_assets_from_hosts_attaches_per_host_attributes() -> None:
    assets = assets_from_hosts(
        ["vpn.example.com"],
        apex="example.com",
        source_tool="amass-passive",
        tool_version="v5.1.1",
        method=DiscoveryMethod.AMASS_PASSIVE,
        consent_ref="C1",
        now=NOW,
        attributes_for={"vpn.example.com": {"addresses": ["203.0.113.5"]}},
    )
    assert assets[0].attributes == {"addresses": ["203.0.113.5"]}
