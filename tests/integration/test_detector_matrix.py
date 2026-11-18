from __future__ import annotations

import httpx
import pytest

from p2c.scanning.catalog import CheckId
from p2c.scanning.httpx_probe import HttpProbe, checks_for_probe
from p2c.scanning.tls import TlsInspector, evaluate_tls

pytestmark = pytest.mark.integration

HTTP_BASE = "http://127.0.0.1:9080"
HOST = "127.0.0.1"


def _require_matrix() -> None:
    try:
        httpx.get(f"{HTTP_BASE}/", timeout=2.0)
    except httpx.HTTPError:
        pytest.skip("matrix target not running: docker compose up -d test-matrix")


def _probe(path: str) -> HttpProbe:
    _require_matrix()
    response = httpx.get(f"{HTTP_BASE}{path}", timeout=5.0)
    cookies = tuple(v for k, v in response.headers.multi_items() if k.lower() == "set-cookie")
    return HttpProbe(
        url=str(response.url),
        host=HOST,
        scheme="https",
        status_code=response.status_code,
        headers=dict(response.headers),
        set_cookie=cookies,
    )


def _tls(port: int) -> list[CheckId]:
    _require_matrix()
    return evaluate_tls(TlsInspector().inspect(HOST, port))




def test_a_self_signed_endpoint_is_reported() -> None:
    assert CheckId.SELF_SIGNED_CERTIFICATE in _tls(9443)


def test_a_private_ca_leaf_raises_nothing() -> None:
    assert _tls(9444) == []


def test_a_weak_rsa_key_is_reported() -> None:
    checks = _tls(9445)
    assert CheckId.WEAK_CERTIFICATE_KEY in checks


def test_a_strong_rsa_key_is_not() -> None:
    assert CheckId.WEAK_CERTIFICATE_KEY not in _tls(9446)


def test_an_approved_curve_is_not_weak() -> None:
    assert CheckId.WEAK_CERTIFICATE_KEY not in _tls(9447)


def test_an_expired_certificate_is_reported_off_the_wire() -> None:
    assert CheckId.EXPIRED_CERTIFICATE in _tls(9449)


def test_an_endpoint_the_stack_cannot_negotiate_is_inconclusive() -> None:
    _require_matrix()
    with pytest.raises(OSError):
        TlsInspector().inspect(HOST, 9448)




def test_the_bare_endpoint_reports_every_header_read() -> None:
    checks = set(checks_for_probe(_probe("/")))
    assert CheckId.MISSING_PERMISSIONS_POLICY in checks
    assert CheckId.MISSING_HSTS in checks


def test_the_clean_control_reports_nothing() -> None:
    assert checks_for_probe(_probe("/clean")) == []


def test_one_absent_header_is_isolated() -> None:
    assert set(checks_for_probe(_probe("/no-permissions-policy"))) == {CheckId.MISSING_PERMISSIONS_POLICY}


def test_a_repeated_set_cookie_header_survives_the_wire() -> None:
    probe = _probe("/cookie-secure")
    assert len(probe.set_cookie) == 2
    assert CheckId.INSECURE_COOKIE not in checks_for_probe(probe)


def test_a_cookie_without_secure_is_reported_off_the_wire() -> None:
    assert CheckId.INSECURE_COOKIE in checks_for_probe(_probe("/cookie-insecure"))


def test_a_development_server_header_is_reported() -> None:
    assert CheckId.EXPOSED_DEV_ENVIRONMENT in checks_for_probe(_probe("/dev-server"))


def test_a_development_hostname_alone_is_not() -> None:
    assert CheckId.EXPOSED_DEV_ENVIRONMENT not in checks_for_probe(_probe("/dev-name-only"))




def _path_results(base: str):
    from p2c.scanning.web_paths import WebPathInspector

    _require_matrix()
    inspector = WebPathInspector()
    return (
        inspector.directory_listing(f"{HTTP_BASE}{base}"),
        inspector.sensitive_files(f"{HTTP_BASE}{base}"),
        inspector.login_panel(f"{HTTP_BASE}{base}"),
    )


@pytest.mark.parametrize(
    ("base", "expected"),
    [
        ("/case-dir-pos", {CheckId.DIRECTORY_LISTING_ENABLED}),
        ("/case-dir-neg", set()),
        ("/case-dir-mention", set()),
        ("/case-sens-git", {CheckId.EXPOSED_SENSITIVE_FILE}),
        ("/case-sens-env", {CheckId.EXPOSED_SENSITIVE_FILE}),
        ("/case-sens-dsstore", {CheckId.EXPOSED_SENSITIVE_FILE}),
        ("/case-sens-sql", {CheckId.EXPOSED_SENSITIVE_FILE}),
        ("/case-sens-status", {CheckId.EXPOSED_SENSITIVE_FILE}),
        ("/case-sens-phpinfo", {CheckId.EXPOSED_SENSITIVE_FILE}),
        ("/case-sens-soft404", set()),
        ("/case-login-pos", {CheckId.EXPOSED_LOGIN_PANEL}),
        ("/case-login-auth", {CheckId.EXPOSED_LOGIN_PANEL}),
        ("/case-login-search", set()),
    ],
)
def test_path_detectors_read_the_planted_property_only(base: str, expected: set[CheckId]) -> None:
    from p2c.scanning.web_paths import PathState

    results = _path_results(base)
    assert {c for r in results for c in r.checks} == expected
    one_page = base in ("/case-dir-mention", "/case-sens-soft404")
    catch_all = {CheckId.EXPOSED_LOGIN_PANEL} if one_page else set()
    assert {r.check for r in results if r.state is PathState.UNREAD} == catch_all


def test_a_login_served_on_every_path_leaves_the_login_read_open() -> None:
    from p2c.scanning.web_paths import PathState

    results = _path_results("/case-login-everywhere")
    login = next(r for r in results if r.check is CheckId.EXPOSED_LOGIN_PANEL)
    assert login.state is PathState.UNREAD and not login.checks


def _banner(path: str):
    from datetime import date

    from p2c.scanning.banners import evaluate_banners

    try:
        response = httpx.get(f"http://127.0.0.1:9081{path}", timeout=2.0)
    except httpx.HTTPError:
        pytest.skip("banner target not running: docker compose up -d test-banner")
    return evaluate_banners(dict(response.headers), today=date(2026, 10, 14))


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/current", ()),
        ("/outdated", (CheckId.OUTDATED_EXPOSED_SOFTWARE,)),
        ("/outdated-recent", ()),
        ("/eol", (CheckId.EOL_SOFTWARE_EXPOSED,)),
        ("/php-eol", (CheckId.EOL_SOFTWARE_EXPOSED,)),
    ],
)
def test_banner_detectors_read_the_planted_version(path: str, expected: tuple[CheckId, ...]) -> None:
    from p2c.scanning.banners import BannerState

    result = _banner(path)
    assert result.state is BannerState.READ and result.checks == expected


@pytest.mark.parametrize(("path", "state"), [("/hidden", "no_banner"), ("/cycle-only", "uncovered")])
def test_a_banner_without_a_full_version_stays_unread(path: str, state: str) -> None:
    result = _banner(path)
    assert result.state.value == state and result.checks == ()


@pytest.mark.parametrize(
    ("path", "expected"),
    [("/case-waf-cf", []), ("/case-waf-cookie", []), ("/case-waf-none", [CheckId.WAF_ABSENT])],
)
def test_waf_detector_reads_the_fingerprint(path: str, expected: list[CheckId]) -> None:
    from p2c.scanning.fingerprints import waf_checks

    assert waf_checks(_probe(path)) == expected


def _dns():
    from p2c.scanning.dns_sec import DnspythonResolver

    resolver = DnspythonResolver(nameservers=["127.0.0.1"], port=9053, timeout=2.0)
    try:
        resolver.resolve("axfr-open.test", "SOA")
    except Exception:
        pytest.skip("matrix DNS not running: docker compose up -d test-dns")
    return resolver


def test_an_open_zone_is_transferred_and_a_closed_one_refused() -> None:
    from p2c.scanning.dns_axfr import ZoneTransferInspector

    inspector = ZoneTransferInspector(_dns(), port=9053, allow_internal=True)
    assert inspector.inspect("axfr-open.test") == [CheckId.DNS_ZONE_TRANSFER_OPEN]
    closed = inspector.inspect_detailed("axfr-closed.test")
    assert closed.checks == () and closed.read


@pytest.mark.parametrize(
    ("zone", "expected"),
    [("ddos-cname.test", []), ("ddos-plain.test", [CheckId.NO_DDOS_PROTECTION])],
)
def test_ddos_detector_reads_aliases(zone: str, expected: list[CheckId]) -> None:
    from p2c.scanning.fingerprints import DdosInspector

    result = DdosInspector(_dns()).inspect_detailed(zone)
    assert list(result.checks) == expected and result.read
    assert (result.evidence is not None) == (not expected)


def test_provider_name_servers_alone_leave_the_ddos_read_open() -> None:
    from p2c.scanning.fingerprints import DdosInspector

    result = DdosInspector(_dns()).inspect_detailed("ddos-ns.test")
    assert result.checks == () and not result.read and "name servers only" in (result.evidence or "")


@pytest.mark.parametrize(
    ("zone", "expected"),
    [
        ("email-good.test", []),
        ("email-nospf.test", [CheckId.SPF_MISSING]),
        ("email-dmarc-none.test", [CheckId.DMARC_MISSING_OR_NONE]),
        ("email-nodmarc.test", [CheckId.DMARC_MISSING_OR_NONE]),
        ("email-nodkim.test", [CheckId.DKIM_MISSING]),
        ("email-selector1.test", []),
    ],
)
def test_email_detectors_read_the_planted_record(zone: str, expected: list[CheckId]) -> None:
    from p2c.scanning.email_dns import EmailDnsInspector

    result = EmailDnsInspector(_dns()).inspect_detailed(zone)
    assert list(result.checks) == expected and result.indeterminate == ()


def test_a_key_outside_the_selector_catalogue_reads_as_missing() -> None:
    from p2c.scanning.email_dns import EmailDnsInspector

    result = EmailDnsInspector(_dns()).inspect_detailed("email-oddselector.test")
    assert list(result.checks) == [CheckId.DKIM_MISSING] and result.indeterminate == ()
