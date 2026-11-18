from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from p2c.scanning.catalog import CheckId

_LEGACY_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
_LEGACY_PROBE = ("TLSv1_1", "DEFAULT:@SECLEVEL=0")
_WEAK_PROBE = ("TLSv1_2", "NULL:aNULL:MD5:RC4:DES:3DES:EXPORT:@SECLEVEL=0")
_LOCAL_LIMITS = frozenset(
    {"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "UNSAFE_LEGACY_RENEGOTIATION_DISABLED"}
)
_WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON", "RC2")

_MIN_RSA_BITS = 3072
_APPROVED_CURVES = frozenset(
    {"secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"}
)


@dataclass(frozen=True)
class TlsInfo:

    version: str
    cipher: str
    not_after: datetime | None = None
    not_before: datetime | None = None
    self_signed: bool | None = None
    key_algorithm: str | None = None
    key_bits: int | None = None
    curve: str | None = None
    issuer: str | None = None
    subject: str | None = None
    legacy_accepted: bool | None = None
    weak_accepted: bool | None = None


def evaluate_tls(info: TlsInfo, *, now: datetime | None = None) -> list[CheckId]:
    at = now or datetime.now(UTC)
    checks: list[CheckId] = []
    if info.version in _LEGACY_VERSIONS or info.legacy_accepted:
        checks.append(CheckId.LEGACY_TLS_VERSION)
    upper = info.cipher.upper()
    if any(marker in upper for marker in _WEAK_CIPHER_MARKERS) or info.weak_accepted:
        checks.append(CheckId.WEAK_TLS_CIPHER)
    if (info.not_after is not None and info.not_after < at) or (
        info.not_before is not None and info.not_before > at
    ):
        checks.append(CheckId.EXPIRED_CERTIFICATE)
    if info.self_signed:
        checks.append(CheckId.SELF_SIGNED_CERTIFICATE)
    if _key_is_weak(info):
        checks.append(CheckId.WEAK_CERTIFICATE_KEY)
    return checks


def _key_is_weak(info: TlsInfo) -> bool:
    if info.key_algorithm is None:
        return False
    if info.key_algorithm == "dsa":
        return True
    if info.key_algorithm == "rsa":
        return info.key_bits is not None and info.key_bits < _MIN_RSA_BITS
    if info.key_algorithm == "ec":
        return info.curve is not None and info.curve not in _APPROVED_CURVES
    return False


def _context(probe: tuple[str, str] | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        if probe is not None:
            ctx.maximum_version = getattr(ssl.TLSVersion, probe[0])
    if probe is not None:
        ctx.set_ciphers(probe[1])
    return ctx


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> tuple[str, str, bytes | None]:
    with (
        socket.create_connection((host, port), timeout=timeout) as sock,
        ctx.wrap_socket(sock, server_hostname=host) as tls_sock,
    ):
        cipher_tuple = tls_sock.cipher()
        return (
            tls_sock.version() or "",
            cipher_tuple[0] if cipher_tuple else "",
            tls_sock.getpeercert(binary_form=True),
        )


def _accepts(host: str, port: int, probe: tuple[str, str], timeout: float) -> bool | None:
    try:
        ctx = _context(probe)
    except ssl.SSLError:
        return None
    for _attempt in range(2):
        try:
            _handshake(host, port, ctx, timeout)
        except ssl.SSLEOFError:
            continue
        except ssl.SSLError as exc:
            if getattr(exc, "reason", None) in _LOCAL_LIMITS:
                return None
            return False
        except OSError:
            return None
        return True
    return None


class TlsInspector:

    def inspect(self, host: str, port: int = 443, *, timeout: float = 10.0) -> TlsInfo:
        try:
            version, cipher, der = _handshake(host, port, _context(), timeout)
        except ssl.SSLError:
            version, cipher, der = _handshake(host, port, _context(_LEGACY_PROBE), timeout)
        legacy = True if version in _LEGACY_VERSIONS else _accepts(host, port, _LEGACY_PROBE, timeout)
        weak = _accepts(host, port, _WEAK_PROBE, timeout)
        facts = _parse_certificate(der)
        return TlsInfo(
            version=version,
            cipher=cipher,
            not_after=facts.not_after,
            not_before=facts.not_before,
            self_signed=facts.self_signed,
            key_algorithm=facts.key_algorithm,
            key_bits=facts.key_bits,
            curve=facts.curve,
            issuer=facts.issuer,
            subject=facts.subject,
            legacy_accepted=legacy,
            weak_accepted=weak,
        )


@dataclass(frozen=True)
class _CertificateFacts:

    not_after: datetime | None = None
    not_before: datetime | None = None
    self_signed: bool | None = None
    key_algorithm: str | None = None
    key_bits: int | None = None
    curve: str | None = None
    issuer: str | None = None
    subject: str | None = None


def _parse_certificate(der: bytes | None) -> _CertificateFacts:
    if not der:
        return _CertificateFacts()
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return _CertificateFacts()
    algorithm, bits, curve = _public_key_strength(cert)
    return _CertificateFacts(
        not_after=cert.not_valid_after_utc,
        not_before=cert.not_valid_before_utc,
        self_signed=_is_self_signed(cert),
        key_algorithm=algorithm,
        key_bits=bits,
        curve=curve,
        issuer=cert.issuer.rfc4514_string(),
        subject=cert.subject.rfc4514_string(),
    )


def _is_self_signed(cert: x509.Certificate) -> bool | None:
    if cert.issuer != cert.subject:
        return False
    key = cert.public_key()
    digest = cert.signature_hash_algorithm
    try:
        if isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes)
        elif digest is None:
            return None
        elif isinstance(key, rsa.RSAPublicKey):
            cert.verify_directly_issued_by(cert)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(digest))
        else:
            return None
    except InvalidSignature:
        return False
    except (UnsupportedAlgorithm, TypeError, ValueError):
        return None
    return True


def _public_key_strength(cert: x509.Certificate) -> tuple[str | None, int | None, str | None]:
    try:
        key = cert.public_key()
    except (UnsupportedAlgorithm, ValueError):
        return None, None, None
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa", key.key_size, None
    if isinstance(key, dsa.DSAPublicKey):
        return "dsa", key.key_size, None
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ec", key.curve.key_size, key.curve.name
    if isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        return "eddsa", None, None
    return None, None, None
