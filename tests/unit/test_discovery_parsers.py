from __future__ import annotations

import json

import pytest

from p2c.discovery.amass import parse_amass_names
from p2c.discovery.base import DiscoveryError
from p2c.discovery.crtsh import parse_crtsh
from p2c.discovery.dnsx import parse_dnsx
from p2c.discovery.subfinder import parse_subfinder

SUBFINDER_JSONL = """\
{"host":"www.example.com","input":"example.com","source":"crtsh"}
{"host":"api.example.com","input":"example.com","source":"dnsdumpster"}

not-json-should-be-skipped
{"host":"mail.example.com","input":"example.com","source":"hackertarget"}
{"input":"example.com","source":"nohost"}
"""

DNSX_JSONL = """\
{"host":"www.example.com","a":["93.184.216.34"],"status_code":"NOERROR"}
{"host":"api.example.com","a":["93.184.216.35"],"cname":["api-lb.example.com"],"status_code":"NOERROR"}
{"host":"dead.example.com","status_code":"NXDOMAIN"}
"""

AMASS_NAMES = "www.example.com\nvpn.example.com\n\n  api.example.com  \n"

CRTSH_JSON = """\
[{"common_name":"www.example.com","name_value":"www.example.com\\nexample.com","issuer_name":"Le"},
 {"common_name":"*.example.com","name_value":"*.example.com","issuer_name":"x"},
 {"common_name":"api.example.com","name_value":"api.example.com","issuer_name":"x"}]
"""


def test_parse_subfinder_extracts_hosts_and_skips_junk() -> None:
    assert parse_subfinder(SUBFINDER_JSONL) == [
        "www.example.com",
        "api.example.com",
        "mail.example.com",
    ]


def test_parse_subfinder_empty() -> None:
    assert parse_subfinder("") == []


def test_parse_dnsx_records() -> None:
    resolutions = parse_dnsx(DNSX_JSONL)
    assert resolutions["www.example.com"] == {"a": ["93.184.216.34"]}
    assert resolutions["api.example.com"]["cname"] == ["api-lb.example.com"]
    assert resolutions["dead.example.com"] == {}


def test_parse_amass_names() -> None:
    assert parse_amass_names(AMASS_NAMES) == ["www.example.com", "vpn.example.com", "api.example.com"]
    assert parse_amass_names("") == []


def test_parse_crtsh_flattens_name_value_and_common_name() -> None:
    hosts = parse_crtsh(CRTSH_JSON)
    assert "example.com" in hosts
    assert "www.example.com" in hosts
    assert "*.example.com" in hosts
    assert "api.example.com" in hosts


def test_parse_crtsh_drops_ip_san_third_party_leak() -> None:
    payload = json.dumps([{"name_value": "api.example.com\n203.0.113.9", "common_name": "shared-cdn.net"}])
    hosts = parse_crtsh(payload)
    assert "api.example.com" in hosts
    assert "203.0.113.9" not in hosts
    assert "2001:db8::1" not in parse_crtsh(json.dumps([{"name_value": "2001:db8::1"}]))


def test_parse_crtsh_bad_json_raises_not_empty() -> None:
    with pytest.raises(DiscoveryError):
        parse_crtsh("<html>rate limited</html>")
    with pytest.raises(DiscoveryError):
        parse_crtsh("{}")
    assert parse_crtsh("[]") == []
