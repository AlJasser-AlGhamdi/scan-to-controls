from __future__ import annotations

import pytest

from p2c.scanning.catalog import CheckId
from p2c.scanning.dns_axfr import ZoneTransferInspector
from p2c.scanning.fingerprints import DdosInspector, waf_checks, waf_signature
from p2c.scanning.httpx_probe import HttpProbe
from p2c.sovereignty.egress_guard import EgressBlocked

DOMAIN = "example.com"


class NoAnswer(Exception):
    pass


class NXDOMAIN(Exception):
    pass


class Timeout(Exception):
    pass


class TransferError(Exception):
    pass


class FakeResolver:
    def __init__(self, answers: dict[tuple[str, str], object]) -> None:
        self._answers = answers

    def resolve(self, name: str, rdtype: str) -> list[str]:
        answer = self._answers.get((name, rdtype), NoAnswer())
        if isinstance(answer, BaseException):
            raise answer
        return list(answer)


def _probe(headers: dict[str, str], cookies: tuple[str, ...] = (), status: int = 200) -> HttpProbe:
    return HttpProbe(
        url="https://x.example/",
        host="x.example",
        scheme="https",
        status_code=status,
        headers=headers,
        set_cookie=cookies,
    )




@pytest.mark.parametrize(
    ("headers", "cookies", "provider"),
    [
        ({"CF-RAY": "8a1b"}, (), "Cloudflare"),
        ({"Server": "cloudflare"}, (), "Cloudflare"),
        ({"X-Sucuri-ID": "1"}, (), "Sucuri"),
        ({}, ("incap_ses_123=abc; path=/",), "Imperva Incapsula"),
        ({}, ("TS01a2b3c4=1; path=/",), "F5 BIG-IP ASM"),
    ],
)
def test_waf_signatures_are_recognised(headers, cookies, provider) -> None:
    signature = waf_signature(headers, cookies)
    assert signature is not None and signature.startswith(provider)
    assert waf_checks(_probe(headers, cookies)) == []


@pytest.mark.parametrize(
    ("headers", "cookies"),
    [({"Server": "AkamaiGHost"}, ()), ({"Server": "BigIP"}, ()), ({}, ("BIGipServerpool=1234; path=/",))],
)
def test_a_cdn_edge_or_load_balancer_leaves_the_waf_read_open(headers, cookies) -> None:
    from p2c.scanning.fingerprints import waf_undecided

    assert waf_signature(headers, cookies) is None
    assert waf_checks(_probe(headers, cookies)) == [] and waf_undecided(_probe(headers, cookies))


def test_no_signature_means_waf_absent() -> None:
    assert waf_checks(_probe({"Server": "nginx"})) == [CheckId.WAF_ABSENT]


def test_waf_read_needs_a_received_response() -> None:
    assert waf_checks(_probe({}, status=0)) == []




def test_provider_name_servers_alone_leave_the_read_open() -> None:
    resolver = FakeResolver({(DOMAIN, "NS"): ["ada.ns.cloudflare.com.", "bob.ns.cloudflare.com."]})
    result = DdosInspector(resolver).inspect_detailed(DOMAIN)
    assert result.checks == () and not result.read
    assert result.evidence is not None and "Cloudflare" in result.evidence


def test_an_akamai_edge_still_counts_as_ddos_protection() -> None:
    resolver = FakeResolver({(DOMAIN, "NS"): ["ns1.example.com."]})
    result = DdosInspector(resolver).inspect_detailed(DOMAIN, {"Server": "AkamaiGHost"})
    assert result.read and result.checks == ()


def test_edge_alias_is_protection() -> None:
    resolver = FakeResolver(
        {(DOMAIN, "NS"): ["ns1.example.com."], (f"www.{DOMAIN}", "CNAME"): ["d111.cloudfront.net."]}
    )
    assert DdosInspector(resolver).inspect(DOMAIN) == []


def test_plain_dns_with_definitive_answers_is_no_protection() -> None:
    resolver = FakeResolver({(DOMAIN, "NS"): ["ns1.example.com.", "ns2.example.com."]})
    assert DdosInspector(resolver).inspect(DOMAIN) == [CheckId.NO_DDOS_PROTECTION]


def test_an_unread_name_server_record_is_inconclusive() -> None:
    resolver = FakeResolver({(DOMAIN, "NS"): Timeout()})
    result = DdosInspector(resolver).inspect_detailed(DOMAIN)
    assert result.checks == () and not result.read


def test_a_provider_header_is_protection_without_dns() -> None:
    resolver = FakeResolver({(DOMAIN, "NS"): Timeout()})
    assert DdosInspector(resolver).inspect(DOMAIN, headers={"x-amz-cf-id": "abc"}) == []


def test_ddos_egress_block_is_never_swallowed() -> None:
    resolver = FakeResolver({(DOMAIN, "NS"): EgressBlocked("8.8.8.8")})
    with pytest.raises(EgressBlocked):
        DdosInspector(resolver).inspect(DOMAIN)




def _axfr(transfers: dict[str, object], ns: object | None = None) -> ZoneTransferInspector:
    answers: dict[tuple[str, str], object] = {
        (DOMAIN, "NS"): ns if ns is not None else [f"{s}." for s in transfers]
    }
    by_address: dict[str, object] = {}
    for i, (server, result) in enumerate(transfers.items()):
        answers[(server, "A")] = [f"10.0.0.{i + 1}"]
        by_address[f"10.0.0.{i + 1}"] = result

    def transfer(address: str, zone: str, port: int) -> list[str]:
        result = by_address[address]
        if isinstance(result, BaseException):
            raise result
        return list(result)

    return ZoneTransferInspector(FakeResolver(answers), transfer, allow_internal=True)


def test_a_server_that_hands_out_the_zone_is_open() -> None:
    result = _axfr({"ns1.example.com": ["@", "www", "mail", "vpn"]}).inspect_detailed(DOMAIN)
    assert result.checks == (CheckId.DNS_ZONE_TRANSFER_OPEN,) and result.n_names == 4


def test_a_refusal_from_every_server_is_a_definitive_negative() -> None:
    inspector = _axfr({"ns1.example.com": TransferError(), "ns2.example.com": ConnectionRefusedError()})
    result = inspector.inspect_detailed(DOMAIN)
    assert result.checks == () and result.read


def test_a_timeout_is_not_a_refusal() -> None:
    inspector = _axfr({"ns1.example.com": TransferError(), "ns2.example.com": TimeoutError()})
    result = inspector.inspect_detailed(DOMAIN)
    assert result.checks == () and not result.read


def test_one_open_server_is_enough() -> None:
    inspector = _axfr({"ns1.example.com": TransferError(), "ns2.example.com": ["@", "db"]})
    assert inspector.inspect(DOMAIN) == [CheckId.DNS_ZONE_TRANSFER_OPEN]


def test_an_apex_only_transfer_is_an_answer_not_a_refusal() -> None:
    result = _axfr({"ns1.example.com": ["@"]}).inspect_detailed(DOMAIN)
    assert result.checks == () and not result.read


def test_unread_name_servers_are_inconclusive() -> None:
    result = _axfr({}, ns=Timeout()).inspect_detailed(DOMAIN)
    assert result.checks == () and not result.read


def test_internal_name_server_addresses_are_not_contacted() -> None:
    contacted: list[str] = []

    def transfer(address: str, zone: str, port: int) -> list[str]:
        contacted.append(address)
        return ["@", "www"]

    resolver = FakeResolver(
        {(DOMAIN, "NS"): ["ns1.example.com."], ("ns1.example.com", "A"): ["192.168.1.10"]}
    )
    result = ZoneTransferInspector(resolver, transfer).inspect_detailed(DOMAIN)
    assert contacted == [] and result.checks == () and not result.read


@pytest.mark.parametrize(
    "address", ["100.64.0.1", "::ffff:10.0.0.1", "224.0.0.1", "not-an-address", "fe80::1"]
)
def test_only_global_unicast_name_server_addresses_are_contacted(address: str) -> None:
    from p2c.scanning.dns_axfr import _internal

    assert _internal(address)


def test_a_global_address_is_contacted() -> None:
    from p2c.scanning.dns_axfr import _internal

    assert not _internal("8.8.8.8")




def test_an_x_cdn_header_counts_only_with_the_incapsula_value() -> None:
    assert waf_signature({"X-CDN": "Incapsula"}) is not None
    assert waf_signature({"X-CDN": "some-other-cdn"}) is None


def test_cdn_only_headers_are_not_a_waf() -> None:
    assert waf_signature({"X-Azure-Ref": "0abc", "X-Akamai-Transformed": "9 - 0 pmb=mRUM,1"}) is None


def test_the_alias_chain_is_followed_to_the_provider() -> None:
    resolver = FakeResolver(
        {
            (DOMAIN, "NS"): ["ns1.example.com."],
            (f"www.{DOMAIN}", "CNAME"): ["www.example.com.cdn.cloudflare.net."],
        }
    )
    result = DdosInspector(resolver).inspect_detailed(DOMAIN)
    assert result.checks == () and "Cloudflare" in (result.evidence or "")
    hop = FakeResolver(
        {
            (DOMAIN, "NS"): ["ns1.example.com."],
            (f"www.{DOMAIN}", "CNAME"): ["edge.example.net."],
            ("edge.example.net", "CNAME"): ["d1.cloudfront.net."],
        }
    )
    assert DdosInspector(hop).inspect(DOMAIN) == []


def test_an_ipv6_only_name_server_is_reached() -> None:
    contacted: list[str] = []

    def transfer(address: str, zone: str, port: int) -> list[str]:
        contacted.append(address)
        return ["@", "www"]

    resolver = FakeResolver(
        {(DOMAIN, "NS"): ["ns1.example.com."], ("ns1.example.com", "AAAA"): ["2001:4860::1"]}
    )
    assert ZoneTransferInspector(resolver, transfer).inspect(DOMAIN) == [CheckId.DNS_ZONE_TRANSFER_OPEN]
    assert contacted == ["2001:4860::1"]


def test_a_name_server_without_addresses_is_not_a_refusal() -> None:
    resolver = FakeResolver({(DOMAIN, "NS"): ["ns1.example.com."]})
    result = ZoneTransferInspector(resolver, lambda a, z, p: []).inspect_detailed(DOMAIN)
    assert result.checks == () and not result.read


def test_a_name_server_address_carrying_ipv4_inside_ipv6_is_never_contacted() -> None:
    from p2c.scanning.dns_axfr import _internal

    assert _internal("64:ff9b::a00:1") and _internal("::a00:1")
    assert not _internal("2001:4860:4860::8888")
