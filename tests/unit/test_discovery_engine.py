from __future__ import annotations

from datetime import UTC, datetime

import pytest

from p2c.discovery.dnsx import DnsxResolver
from p2c.discovery.engine import DiscoveryEngine, synthetic_engine
from p2c.discovery.normalize import assets_from_hosts
from p2c.discovery.runner import CommandResult
from p2c.discovery.synthetic import SyntheticAsset, SyntheticProfile
from p2c.schemas.enums import DiscoveryMethod
from p2c.schemas.models import Asset
from p2c.sovereignty.egress_guard import EgressBlocked

NOW = datetime(2026, 1, 1, tzinfo=UTC)


class _Runner:

    def __init__(self, stdout: str = "", *, exc: Exception | None = None) -> None:
        self._stdout = stdout
        self._exc = exc

    def run(self, argv: list[str], *, stdin: str | None = None, timeout: float = 120.0) -> CommandResult:
        if self._exc is not None:
            raise self._exc
        return CommandResult(list(argv), 0, self._stdout, "")


class _CrtshLike:

    source_tool = "crt.sh"

    def discover(self, target: str, *, consent_ref: str, now: datetime | None = None) -> list[Asset]:
        return assets_from_hosts(
            ["www.example.com"],
            apex=target,
            source_tool="crt.sh",
            tool_version="crt.sh-json",
            method=DiscoveryMethod.CRTSH,
            consent_ref=consent_ref,
            now=now,
        )


class _GoodSource:
    source_tool = "good"

    def discover(self, target: str, *, consent_ref: str, now: datetime | None = None) -> list[Asset]:
        return assets_from_hosts(
            ["www.example.com"],
            apex=target,
            source_tool="good",
            tool_version="1",
            method=DiscoveryMethod.SUBFINDER,
            consent_ref=consent_ref,
            now=now,
        )


class _BadSource:
    source_tool = "bad"

    def discover(self, target: str, *, consent_ref: str, now: datetime | None = None) -> list[Asset]:
        raise RuntimeError("source exploded")


class _EgressSource:
    source_tool = "crt.sh"

    def discover(self, target: str, *, consent_ref: str, now: datetime | None = None) -> list[Asset]:
        raise EgressBlocked("crt.sh")


def test_engine_merges_and_isolates_source_errors() -> None:
    engine = DiscoveryEngine([_GoodSource(), _BadSource()], clock=lambda: NOW)
    result = engine.discover("example.com", consent_ref="C1")
    assert result.asset_count == 1
    assert result.assets[0].value == "www.example.com"
    assert any("bad" in e for e in result.errors)
    assert result.sources == ["good", "bad"]


def test_engine_propagates_egress_block() -> None:
    with pytest.raises(EgressBlocked):
        DiscoveryEngine([_EgressSource()]).discover("example.com", consent_ref="C1")


def test_synthetic_engine_from_profile() -> None:
    profile = SyntheticProfile(
        profile_id="p1",
        apex="example.com",
        assets=[
            SyntheticAsset(value="www.example.com"),
            SyntheticAsset(value="api.example.com", attributes={"service": "http"}),
            SyntheticAsset(value="evil.com"),
        ],
    )
    result = synthetic_engine(profile, clock=lambda: NOW).discover("example.com", consent_ref="C1")
    assert {a.value for a in result.assets} == {"www.example.com", "api.example.com"}
    for asset in result.assets:
        assert asset.attributes["discovered_by"][0]["source_tool"] == "synthetic"
    api = next(a for a in result.assets if a.value == "api.example.com")
    assert api.attributes["service"] == "http"


def test_synthetic_engine_is_deterministic_without_explicit_clock() -> None:
    profile = SyntheticProfile(
        profile_id="p1", apex="example.com", assets=[SyntheticAsset(value="a.example.com")]
    )
    r1 = synthetic_engine(profile).discover("example.com", consent_ref="C1")
    r2 = synthetic_engine(profile).discover("example.com", consent_ref="C1")
    assert r1.model_dump() == r2.model_dump()
    assert r1.assets[0].first_seen == NOW


def test_engine_dnsx_preserves_provenance_on_every_asset() -> None:
    engine = DiscoveryEngine(
        [_GoodSource(), _CrtshLike()],
        resolver=DnsxResolver(_Runner('{"host":"www.example.com","a":["93.184.216.34"]}\n')),
        clock=lambda: NOW,
    )
    result = engine.discover("example.com", consent_ref="C1")
    assert result.asset_count == 1
    asset = result.assets[0]
    assert {d["source_tool"] for d in asset.attributes["discovered_by"]} == {"good", "crt.sh"}
    assert asset.attributes["resolved"] is True
    assert asset.attributes["dns"]["a"] == ["93.184.216.34"]


def test_engine_isolates_dnsx_failure_into_errors() -> None:
    engine = DiscoveryEngine(
        [_GoodSource()],
        resolver=DnsxResolver(_Runner(exc=RuntimeError("dnsx crashed"))),
        clock=lambda: NOW,
    )
    result = engine.discover("example.com", consent_ref="C1")
    assert result.asset_count == 1
    assert any("dnsx" in e for e in result.errors)


def test_engine_reraises_egress_block_on_resolver_path() -> None:
    engine = DiscoveryEngine(
        [_GoodSource()], resolver=DnsxResolver(_Runner(exc=EgressBlocked("resolver"))), clock=lambda: NOW
    )
    with pytest.raises(EgressBlocked):
        engine.discover("example.com", consent_ref="C1")
