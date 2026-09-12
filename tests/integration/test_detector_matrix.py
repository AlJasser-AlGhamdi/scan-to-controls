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
