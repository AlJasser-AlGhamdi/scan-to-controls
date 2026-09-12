from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
import respx

from p2c.discovery.amass import AmassSource
from p2c.discovery.base import DiscoveryError
from p2c.discovery.crtsh import CrtshSource
from p2c.discovery.dnsx import DnsxResolver
from p2c.discovery.normalize import assets_from_hosts
from p2c.discovery.runner import CommandResult
from p2c.discovery.subfinder import SubfinderSource
from p2c.schemas.enums import DiscoveryMethod

NOW = datetime(2026, 1, 1, tzinfo=UTC)

SUBFINDER_JSONL = '{"host":"www.example.com","source":"crtsh"}\n{"host":"api.example.com","source":"dnsx"}\n'
AMASS_NAMES = "vpn.example.com\nwww.example.com\n"
DNSX_JSONL = '{"host":"www.example.com","a":["93.184.216.34"]}\n'
CRTSH_JSON = '[{"common_name":"www.example.com","name_value":"www.example.com\\nexample.com"}]'


class FakeRunner:
    def __init__(self, stdout: str = "", *, returncode: int = 0) -> None:
        self._stdout = stdout
        self._rc = returncode
        self.calls: list[tuple[list[str], str | None]] = []

    def run(self, argv: list[str], *, stdin: str | None = None, timeout: float = 120.0) -> CommandResult:
        self.calls.append((list(argv), stdin))
        return CommandResult(list(argv), self._rc, self._stdout, "")


def test_subfinder_source() -> None:
    runner = FakeRunner(SUBFINDER_JSONL)
    assets = SubfinderSource(runner).discover("example.com", consent_ref="C1", now=NOW)
    assert {a.value for a in assets} == {"www.example.com", "api.example.com"}
    assert all(a.source_tool == "subfinder" and a.tool_version == "v2.14.0" for a in assets)
    assert runner.calls[0][0] == ["subfinder", "-silent", "-json", "-d", "example.com"]


def test_amass_source_two_step_flow() -> None:
    runner = FakeRunner(AMASS_NAMES)
    assets = AmassSource(runner).discover("example.com", consent_ref="C1", now=NOW)
    assert {a.value for a in assets} == {"vpn.example.com", "www.example.com"}
    assert all(a.source_tool == "amass-passive" and a.tool_version == "v5.1.1" for a in assets)
    assert runner.calls[0][0][:2] == ["amass", "enum"]
    assert runner.calls[1][0][:2] == ["amass", "subs"]
    assert "-names" in runner.calls[1][0]


def test_dnsx_resolver_marks_resolved_and_unresolved() -> None:
    assets = assets_from_hosts(
        ["www.example.com", "dead.example.com"],
        apex="example.com",
        source_tool="subfinder",
        tool_version="v2.14.0",
        method=DiscoveryMethod.SUBFINDER,
        consent_ref="C1",
        now=NOW,
    )
    runner = FakeRunner(DNSX_JSONL)
    resolved = DnsxResolver(runner).resolve(assets)
    www = next(a for a in resolved if a.value == "www.example.com")
    dead = next(a for a in resolved if a.value == "dead.example.com")
    assert www.attributes["resolved"] is True
    assert www.attributes["dns"]["a"] == ["93.184.216.34"]
    assert dead.attributes["resolved"] is False
    assert dead.attributes["dns"] == {}
    assert runner.calls[0][1] is not None and "www.example.com" in runner.calls[0][1]


def test_dnsx_resolver_no_hosts_is_noop() -> None:
    assert DnsxResolver(FakeRunner("")).resolve([]) == []


@respx.mock
def test_crtsh_source_parses() -> None:
    respx.route(host="crt.sh").mock(return_value=httpx.Response(200, text=CRTSH_JSON))
    assets = CrtshSource().discover("example.com", consent_ref="C1", now=NOW)
    values = {a.value for a in assets}
    assert {"example.com", "www.example.com"} <= values
    assert all(a.source_tool == "crt.sh" for a in assets)


@respx.mock
def test_crtsh_source_raises_on_error_status() -> None:
    respx.route(host="crt.sh").mock(return_value=httpx.Response(502))
    with pytest.raises(DiscoveryError, match="502"):
        CrtshSource().discover("example.com", consent_ref="C1", now=NOW)


def test_subfinder_raises_on_nonzero_exit() -> None:
    runner = FakeRunner("", returncode=1)
    with pytest.raises(DiscoveryError, match="subfinder exited 1"):
        SubfinderSource(runner).discover("example.com", consent_ref="C1", now=NOW)


def test_dnsx_raises_on_nonzero_exit() -> None:
    assets = assets_from_hosts(
        ["www.example.com"],
        apex="example.com",
        source_tool="subfinder",
        tool_version="v2.14.0",
        method=DiscoveryMethod.SUBFINDER,
        consent_ref="C1",
        now=NOW,
    )
    with pytest.raises(DiscoveryError, match="dnsx exited 2"):
        DnsxResolver(FakeRunner("", returncode=2)).resolve(assets)


@respx.mock
def test_crtsh_encodes_query_and_rejects_injection() -> None:
    route = respx.route(host="crt.sh").mock(return_value=httpx.Response(200, text=CRTSH_JSON))
    CrtshSource().discover("example.com", consent_ref="C1", now=NOW)
    assert route.calls.last.request.url.params["q"] == "%.example.com"
    with pytest.raises(ValueError, match="invalid target"):
        CrtshSource().discover("example.com&issuer=x", consent_ref="C1", now=NOW)
