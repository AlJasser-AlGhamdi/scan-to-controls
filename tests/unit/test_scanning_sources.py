from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from p2c.scanning.catalog import CheckId
from p2c.scanning.email_dns import DnsRecordAbsent, EmailDnsInspector
from p2c.scanning.headers import analyze_security_headers
from p2c.scanning.httpx_probe import HttpProbe, checks_for_probe, parse_httpx, response_received
from p2c.scanning.ports import classify_port, parse_naabu
from p2c.scanning.tls import TlsInfo, evaluate_tls
from p2c.sovereignty.egress_guard import EgressBlocked

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_analyze_headers_all_missing() -> None:
    assert set(analyze_security_headers({})) == {
        CheckId.MISSING_HSTS,
        CheckId.MISSING_CSP,
        CheckId.MISSING_X_FRAME_OPTIONS,
        CheckId.MISSING_X_CONTENT_TYPE_OPTIONS,
        CheckId.MISSING_REFERRER_POLICY,
        CheckId.MISSING_PERMISSIONS_POLICY,
    }


def test_analyze_headers_present_is_case_insensitive() -> None:
    headers = {
        "Strict-Transport-Security": "max-age=63072000",
        "content-security-policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "PERMISSIONS-POLICY": "geolocation=()",
    }
    assert analyze_security_headers(headers) == []


def test_evaluate_tls_flags() -> None:
    assert evaluate_tls(TlsInfo("TLSv1", "AES128-SHA"), now=NOW) == [CheckId.LEGACY_TLS_VERSION]
    assert evaluate_tls(TlsInfo("TLSv1.2", "ECDHE-RSA-RC4-SHA"), now=NOW) == [CheckId.WEAK_TLS_CIPHER]
    expired = TlsInfo("TLSv1.3", "TLS_AES_256_GCM_SHA384", not_after=NOW - timedelta(days=1))
    assert evaluate_tls(expired, now=NOW) == [CheckId.EXPIRED_CERTIFICATE]
    assert evaluate_tls(TlsInfo("TLSv1.3", "TLS_AES_256_GCM_SHA384"), now=NOW) == []


def test_evaluate_tls_unread_fields_raise_nothing() -> None:
    assert evaluate_tls(TlsInfo("", "", not_after=None), now=NOW) == []


def test_parse_naabu_and_classify() -> None:
    output = (
        '{"host":"h","ip":"10.0.0.1","port":5432}\n{"host":"h","port":22}\nbad\n{"host":"h","port":8080}\n'
    )
    assert parse_naabu(output) == [("h", 5432), ("h", 22), ("h", 8080)]
    assert classify_port(5432) is CheckId.EXPOSED_INTERNAL_PORT
    assert classify_port(22) is CheckId.EXPOSED_MANAGEMENT_PORT
    assert classify_port(23) is CheckId.HIGH_RISK_PORT_OPEN
    assert classify_port(8080) is None


def test_parse_httpx_and_probe_checks() -> None:
    output = '{"url":"http://x/","host":"x","scheme":"http","status_code":200,"header":{"Server":"nginx"}}\n'
    probes = parse_httpx(output)
    assert probes[0].scheme == "http"
    checks = checks_for_probe(probes[0])
    assert CheckId.NO_HTTPS_REDIRECT in checks
    assert CheckId.MISSING_HSTS in checks


def test_parse_httpx_skips_malformed_rows_without_aborting_batch() -> None:
    output = (
        '{"url":"http://a/","scheme":"http","status_code":"weird","tech":null}\n'
        '{"url":"http://b/","host":"b","scheme":"http","status_code":200,"header":{}}\n'
    )
    probes = parse_httpx(output)
    assert [p.host for p in probes] == ["", "b"]
    assert probes[0].status_code == 0 and probes[0].tech == ()


def test_probe_without_a_received_response_yields_no_findings() -> None:
    probe = HttpProbe(url="http://x/", host="x", scheme="http", status_code=0, headers={})
    assert response_received(probe) is False
    assert checks_for_probe(probe) == []


def test_probe_with_a_received_response_and_no_headers_reports_missing() -> None:
    probe = HttpProbe(url="https://x/", host="x", scheme="https", status_code=200, headers={})
    assert response_received(probe) is True
    assert set(checks_for_probe(probe)) == {
        CheckId.MISSING_HSTS,
        CheckId.MISSING_CSP,
        CheckId.MISSING_X_FRAME_OPTIONS,
        CheckId.MISSING_X_CONTENT_TYPE_OPTIONS,
        CheckId.MISSING_REFERRER_POLICY,
        CheckId.MISSING_PERMISSIONS_POLICY,
    }


def test_checks_for_https_probe_with_all_headers() -> None:
    probe = HttpProbe(
        url="https://x/",
        host="x",
        scheme="https",
        status_code=200,
        headers={
            "strict-transport-security": "max-age=1",
            "content-security-policy": "x",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        },
    )
    assert checks_for_probe(probe) == []


class FakeResolver:
    def __init__(
        self, records: dict[str, list[str]], *, failures: dict[str, Exception] | None = None
    ) -> None:
        self._records = records
        self._failures = failures or {}

    def resolve_txt(self, name: str) -> list[str]:
        if name in self._failures:
            raise self._failures[name]
        if name not in self._records:
            raise DnsRecordAbsent(name)
        return self._records[name]


class NXDOMAIN(Exception):
    pass


class NoAnswer(Exception):
    pass


class Timeout(Exception):
    pass


class NoNameservers(Exception):
    pass


DOMAIN = "example.com"
DKIM_PROBE_COUNT = 9


def test_email_dns_all_missing() -> None:
    result = EmailDnsInspector(FakeResolver({})).inspect_detailed(DOMAIN)
    assert set(result.checks) == {
        CheckId.SPF_MISSING,
        CheckId.DMARC_MISSING_OR_NONE,
        CheckId.DKIM_MISSING,
    }
    assert result.indeterminate == ()


def test_email_dns_definitive_empty_answer_is_absence() -> None:

    class EmptyAnswerResolver:
        def resolve_txt(self, name: str) -> list[str]:
            return []

    checks = EmailDnsInspector(EmptyAnswerResolver()).inspect(DOMAIN)
    assert set(checks) == {CheckId.SPF_MISSING, CheckId.DMARC_MISSING_OR_NONE, CheckId.DKIM_MISSING}


def test_email_dns_dnspython_negative_answers_are_absence() -> None:
    failures: dict[str, Exception] = {DOMAIN: NXDOMAIN(), f"_dmarc.{DOMAIN}": NoAnswer()}
    result = EmailDnsInspector(FakeResolver({}, failures=failures)).inspect_detailed(DOMAIN)
    assert CheckId.SPF_MISSING in result.checks and CheckId.DMARC_MISSING_OR_NONE in result.checks
    assert result.indeterminate == ()


def test_email_dns_timeout_is_not_absence() -> None:
    resolver = FakeResolver({}, failures={DOMAIN: Timeout()})
    result = EmailDnsInspector(resolver).inspect_detailed(DOMAIN)
    assert CheckId.SPF_MISSING not in result.checks
    assert CheckId.DMARC_MISSING_OR_NONE in result.checks
    assert result.indeterminate == (DOMAIN,)


def test_email_dns_servfail_is_not_absence() -> None:
    resolver = FakeResolver({}, failures={f"_dmarc.{DOMAIN}": NoNameservers()})
    result = EmailDnsInspector(resolver).inspect_detailed(DOMAIN)
    assert CheckId.DMARC_MISSING_OR_NONE not in result.checks
    assert CheckId.SPF_MISSING in result.checks
    assert result.indeterminate == (f"_dmarc.{DOMAIN}",)


def test_email_dns_one_unread_selector_blocks_dkim_absence() -> None:
    unread = f"selector1._domainkey.{DOMAIN}"
    resolver = FakeResolver({}, failures={unread: Timeout()})
    result = EmailDnsInspector(resolver).inspect_detailed(DOMAIN)
    assert CheckId.DKIM_MISSING not in result.checks
    assert result.indeterminate == (unread,)


def test_email_dns_resolver_down_yields_no_findings() -> None:

    class DeadResolver:
        def resolve_txt(self, name: str) -> list[str]:
            raise OSError("network unreachable")

    result = EmailDnsInspector(DeadResolver()).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert len(result.indeterminate) == DKIM_PROBE_COUNT + 2


def test_email_dns_egress_block_propagates_and_is_never_silent() -> None:

    class BlockedResolver:
        def resolve_txt(self, name: str) -> list[str]:
            raise EgressBlocked(name)

    with pytest.raises(EgressBlocked):
        EmailDnsInspector(BlockedResolver()).inspect(DOMAIN)


def test_email_dns_all_present() -> None:
    resolver = FakeResolver(
        {
            "example.com": ["v=spf1 include:_spf.example.com -all"],
            "_dmarc.example.com": ["v=DMARC1; p=reject"],
            "default._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIGf..."],
        }
    )
    assert EmailDnsInspector(resolver).inspect("example.com") == []


def test_email_dns_dmarc_policy_none_flagged() -> None:
    resolver = FakeResolver(
        {
            "example.com": ["v=spf1 -all"],
            "_dmarc.example.com": ["v=DMARC1; p=none"],
            "default._domainkey.example.com": ["v=DKIM1; p=abc"],
        }
    )
    assert EmailDnsInspector(resolver).inspect("example.com") == [CheckId.DMARC_MISSING_OR_NONE]
