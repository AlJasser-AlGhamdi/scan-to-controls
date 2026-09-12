from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from p2c.scanning import tls as tls_module
from p2c.scanning.catalog import CheckId
from p2c.scanning.tls import TlsInfo, _parse_certificate, evaluate_tls

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _mint(
    *,
    subject: str = "leaf.example",
    issuer: str | None = None,
    signing_key: object | None = None,
    subject_key: object | None = None,
    not_after: datetime | None = None,
) -> bytes:
    subject_key = subject_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signing_key = signing_key or subject_key
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer or subject))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(not_after or NOW + timedelta(days=365))
    )
    signed = builder.sign(signing_key, hashes.SHA256())
    return signed.public_bytes(serialization.Encoding.DER)


def test_a_truly_self_signed_certificate_is_reported() -> None:
    facts = _parse_certificate(_mint())
    assert facts.self_signed is True
    assert CheckId.SELF_SIGNED_CERTIFICATE in evaluate_tls(
        TlsInfo("TLSv1.3", "TLS_AES_256_GCM_SHA384", self_signed=facts.self_signed), now=NOW
    )


def test_a_ca_issued_certificate_is_not_self_signed() -> None:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    facts = _parse_certificate(_mint(issuer="Example CA", signing_key=ca_key))
    assert facts.self_signed is False
    assert evaluate_tls(TlsInfo("TLSv1.3", "AES", self_signed=False), now=NOW) == []


def test_a_private_ca_certificate_is_not_self_signed_even_though_no_store_trusts_it() -> None:
    internal_ca = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    facts = _parse_certificate(_mint(issuer="Acme Internal Root", signing_key=internal_ca))
    assert facts.self_signed is False


def test_matching_names_with_a_foreign_signature_are_not_self_signed() -> None:
    impostor = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = _mint(subject="same.example", issuer="same.example", signing_key=impostor)
    facts = _parse_certificate(der)
    assert facts.issuer == facts.subject
    assert facts.self_signed is False


def test_an_elliptic_curve_certificate_can_be_self_signed() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    facts = _parse_certificate(_mint(subject_key=key))
    assert facts.self_signed is True


@pytest.mark.parametrize(
    ("bits", "weak"),
    [(1024, True), (2048, False), (4096, False)],
)
def test_rsa_key_sizes_against_the_documented_threshold(bits: int, weak: bool) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    facts = _parse_certificate(_mint(subject_key=key))
    assert (facts.key_algorithm, facts.key_bits) == ("rsa", bits)
    fired = CheckId.WEAK_CERTIFICATE_KEY in evaluate_tls(
        TlsInfo("TLSv1.3", "AES", key_algorithm=facts.key_algorithm, key_bits=facts.key_bits), now=NOW
    )
    assert fired is weak


@pytest.mark.parametrize(
    ("curve", "weak"),
    [(ec.SECP256R1(), False), (ec.SECP384R1(), False), (ec.SECP521R1(), False), (ec.SECP192R1(), True)],
)
def test_elliptic_curves_against_the_approved_set(curve: ec.EllipticCurve, weak: bool) -> None:
    facts = _parse_certificate(_mint(subject_key=ec.generate_private_key(curve)))
    assert facts.key_algorithm == "ec"
    fired = CheckId.WEAK_CERTIFICATE_KEY in evaluate_tls(
        TlsInfo("TLSv1.3", "AES", key_algorithm="ec", key_bits=facts.key_bits, curve=facts.curve), now=NOW
    )
    assert fired is weak


def test_an_unread_key_raises_nothing() -> None:
    assert evaluate_tls(TlsInfo("TLSv1.3", "AES", key_algorithm=None, key_bits=None), now=NOW) == []


def test_the_expiry_is_read_from_the_certificate() -> None:
    expired = _mint(not_after=NOW - timedelta(days=1))
    facts = _parse_certificate(expired)
    assert facts.not_after is not None
    assert facts.not_after < NOW
    assert CheckId.EXPIRED_CERTIFICATE in evaluate_tls(
        TlsInfo("TLSv1.3", "AES", not_after=facts.not_after), now=NOW
    )


def test_a_current_certificate_does_not_fire_the_expiry_check() -> None:
    facts = _parse_certificate(_mint())
    assert facts.not_after is not None
    assert facts.not_after > NOW
    assert evaluate_tls(TlsInfo("TLSv1.3", "AES", not_after=facts.not_after), now=NOW) == []


def test_a_malformed_certificate_yields_no_findings() -> None:
    facts = _parse_certificate(b"not a certificate")
    assert facts == type(facts)()
    assert evaluate_tls(TlsInfo("TLSv1.3", "AES"), now=NOW) == []


def test_an_absent_certificate_yields_no_findings() -> None:
    for der in (None, b""):
        facts = _parse_certificate(der)
        assert facts.self_signed is None
        assert facts.key_algorithm is None
        assert facts.not_after is None


def test_the_inspector_asks_for_the_binary_certificate(monkeypatch: pytest.MonkeyPatch) -> None:
    der = _mint(not_after=NOW - timedelta(days=1))
    calls: list[bool] = []

    class _FakeTls:
        def __enter__(self) -> _FakeTls:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def version(self) -> str:
            return "TLSv1.3"

        def cipher(self) -> tuple[str, str, int]:
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def getpeercert(self, binary_form: bool = False) -> object:
            calls.append(binary_form)
            return der if binary_form else {}

    class _FakeSock:
        def __enter__(self) -> _FakeSock:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: _FakeSock())
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", lambda self, sock, **k: _FakeTls())

    info = tls_module.TlsInspector().inspect("example.test", 443)

    reason = "the inspector must ask for the DER; the dict form is empty under CERT_NONE"
    assert calls == [True], reason
    assert info.not_after is not None, "the expiry must survive the live path, not just the pure one"
    assert CheckId.EXPIRED_CERTIFICATE in evaluate_tls(info, now=NOW)


def test_a_not_yet_valid_certificate_is_reported() -> None:
    future = _mint(not_after=NOW + timedelta(days=800))
    facts = _parse_certificate(future)
    assert facts.not_before is not None
    early = NOW - timedelta(days=30)
    assert CheckId.EXPIRED_CERTIFICATE in evaluate_tls(
        TlsInfo("TLSv1.3", "AES", not_before=facts.not_before), now=early
    )
    assert CheckId.EXPIRED_CERTIFICATE not in evaluate_tls(
        TlsInfo("TLSv1.3", "AES", not_before=facts.not_before), now=NOW
    )
