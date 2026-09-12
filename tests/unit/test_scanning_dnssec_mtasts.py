from __future__ import annotations

import httpx
import pytest

from p2c.scanning.catalog import CheckId
from p2c.scanning.dns_sec import DnssecInspector
from p2c.scanning.mta_sts import MtaStsInspector, MtaStsState, parse_policy
from p2c.sovereignty.egress_guard import EgressBlocked

DOMAIN = "example.com"


class NXDOMAIN(Exception):
    pass


class NoAnswer(Exception):
    pass


class Timeout(Exception):
    pass


class NoNameservers(Exception):
    pass


class FakeResolver:

    def __init__(
        self,
        records: dict[tuple[str, str], list[str]] | None = None,
        *,
        failures: dict[tuple[str, str], Exception] | None = None,
    ) -> None:
        self._records = records or {}
        self._failures = failures or {}

    def resolve(self, name: str, rdtype: str) -> list[str]:
        key = (name, rdtype)
        if key in self._failures:
            raise self._failures[key]
        if key not in self._records:
            raise NoAnswer(f"{name}/{rdtype}")
        return self._records[key]


def test_an_unsigned_zone_is_reported() -> None:
    result = DnssecInspector(FakeResolver()).inspect_detailed(DOMAIN)
    assert result.checks == (CheckId.DNSSEC_MISSING,)
    assert result.fully_read


def test_a_ds_record_means_signed() -> None:
    resolver = FakeResolver({(DOMAIN, "DS"): ["2371 13 2 abcd"]})
    assert DnssecInspector(resolver).inspect(DOMAIN) == []


def test_a_dnskey_alone_means_signed() -> None:
    resolver = FakeResolver({(DOMAIN, "DNSKEY"): ["257 3 13 mdsw..."]})
    assert DnssecInspector(resolver).inspect(DOMAIN) == []


def test_servfail_is_not_absence() -> None:
    failures = {(DOMAIN, "DS"): NoNameservers(DOMAIN), (DOMAIN, "DNSKEY"): NoNameservers(DOMAIN)}
    resolver = FakeResolver(failures=failures)
    result = DnssecInspector(resolver).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert not result.fully_read


def test_a_timeout_is_not_absence() -> None:
    resolver = FakeResolver(failures={(DOMAIN, "DS"): Timeout(DOMAIN), (DOMAIN, "DNSKEY"): Timeout(DOMAIN)})
    assert DnssecInspector(resolver).inspect(DOMAIN) == []


def test_one_unread_lookup_blocks_the_absence_claim() -> None:
    resolver = FakeResolver(failures={(DOMAIN, "DNSKEY"): Timeout(DOMAIN)})
    result = DnssecInspector(resolver).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert result.ds.resolved and not result.dnskey.resolved


def test_nxdomain_is_a_definitive_absence() -> None:
    resolver = FakeResolver(failures={(DOMAIN, "DS"): NXDOMAIN(DOMAIN), (DOMAIN, "DNSKEY"): NXDOMAIN(DOMAIN)})
    assert DnssecInspector(resolver).inspect(DOMAIN) == [CheckId.DNSSEC_MISSING]


def test_an_egress_block_propagates_and_is_never_silent() -> None:
    resolver = FakeResolver(failures={(DOMAIN, "DS"): EgressBlocked("blocked")})
    with pytest.raises(EgressBlocked):
        DnssecInspector(resolver).inspect(DOMAIN)


_RECORD = {("_mta-sts.example.com", "TXT"): ["v=STSv1; id=20260830T000000"]}
_VALID_POLICY = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n"


def _client(handler: object) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_no_record_is_a_definitive_absence() -> None:
    result = MtaStsInspector(FakeResolver()).inspect_detailed(DOMAIN)
    assert result.checks == (CheckId.MTA_STS_MISSING,)
    assert result.state is MtaStsState.RECORD_ABSENT


def test_a_record_that_announces_no_policy_is_also_absence() -> None:
    resolver = FakeResolver({("_mta-sts.example.com", "TXT"): ["v=spf1 -all"]})
    result = MtaStsInspector(resolver).inspect_detailed(DOMAIN)
    assert result.checks == (CheckId.MTA_STS_MISSING,)
    assert result.state is MtaStsState.RECORD_MALFORMED


def test_a_valid_record_and_policy_raise_nothing() -> None:
    client = _client(lambda request: httpx.Response(200, text=_VALID_POLICY))
    result = MtaStsInspector(FakeResolver(_RECORD), client).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert result.state is MtaStsState.POLICY_VALID


def test_an_unreachable_policy_endpoint_raises_nothing() -> None:
    client = _client(lambda request: httpx.Response(404))
    result = MtaStsInspector(FakeResolver(_RECORD), client).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert result.state is MtaStsState.POLICY_UNREACHABLE


def test_a_malformed_policy_raises_nothing_and_keeps_the_body() -> None:
    client = _client(lambda request: httpx.Response(200, text="version: STSv1\nmode: enforce\n"))
    result = MtaStsInspector(FakeResolver(_RECORD), client).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert result.state is MtaStsState.POLICY_UNREACHABLE
    assert result.policy == "version: STSv1\nmode: enforce\n"


def test_a_transport_failure_on_the_policy_raises_nothing() -> None:
    def _boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    result = MtaStsInspector(FakeResolver(_RECORD), _client(_boom)).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert result.state is MtaStsState.POLICY_UNREACHABLE


def test_an_unread_txt_lookup_raises_nothing() -> None:
    resolver = FakeResolver(failures={("_mta-sts.example.com", "TXT"): Timeout(DOMAIN)})
    result = MtaStsInspector(resolver).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert result.state is MtaStsState.UNREAD


def test_the_mta_sts_egress_block_propagates() -> None:
    resolver = FakeResolver(failures={("_mta-sts.example.com", "TXT"): EgressBlocked("blocked")})
    with pytest.raises(EgressBlocked):
        MtaStsInspector(resolver).inspect(DOMAIN)


@pytest.mark.parametrize(
    ("body", "valid"),
    [
        (_VALID_POLICY, True),
        ("version: STSv1\nmode: none\nmax_age: 604800\n", True),
        ("version: STSv1\nmode: enforce\nmax_age: 604800\n", False),
        ("version: STSv2\nmode: enforce\nmx: m\nmax_age: 1\n", False),
        ("version: STSv1\nmode: sometimes\nmx: m\nmax_age: 1\n", False),
        ("version: STSv1\nmode: enforce\nmx: m\nmax_age: soon\n", False),
        ("", False),
    ],
)
def test_policy_parsing_against_the_rfc_fields(body: str, valid: bool) -> None:
    assert parse_policy(body) is valid


def test_two_records_are_an_absent_policy() -> None:
    resolver = FakeResolver({("_mta-sts.example.com", "TXT"): ["v=STSv1; id=a", "v=STSv1; id=b"]})
    result = MtaStsInspector(resolver).inspect_detailed(DOMAIN)
    assert result.checks == (CheckId.MTA_STS_MISSING,)
    assert result.state is MtaStsState.RECORD_MALFORMED


def test_a_policy_that_enforces_nothing_is_a_finding() -> None:
    body = "version: STSv1\nmode: none\nmax_age: 604800\n"
    client = _client(lambda request: httpx.Response(200, text=body))
    result = MtaStsInspector(FakeResolver(_RECORD), client).inspect_detailed(DOMAIN)
    assert result.checks == (CheckId.MTA_STS_MISSING,)
    assert result.state is MtaStsState.POLICY_NOT_ENFORCING


def test_testing_mode_is_not_a_finding() -> None:
    body = "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 604800\n"
    client = _client(lambda request: httpx.Response(200, text=body))
    assert MtaStsInspector(FakeResolver(_RECORD), client).inspect_detailed(DOMAIN).checks == ()
