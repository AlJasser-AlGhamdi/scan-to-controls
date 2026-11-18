from __future__ import annotations

import socket
import ssl
import subprocess
import threading
import warnings
from collections.abc import Iterator
from pathlib import Path

import pytest

from p2c.scanning.catalog import CheckId
from p2c.scanning.tls import TlsInspector, evaluate_tls

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def certificate(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    folder = tmp_path_factory.mktemp("tls")
    key, cert = folder / "k.pem", folder / "c.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
         "-days", "2", "-subj", "/CN=probe.test"],
        check=True,
        capture_output=True,
    )
    return cert, key


def _serve(certificate: tuple[Path, Path], maximum: ssl.TLSVersion, ciphers: str) -> int:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*map(str, certificate))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.maximum_version = maximum
    ctx.set_ciphers(ciphers)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()

    def run() -> None:
        while True:
            conn, _ = listener.accept()
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass

    threading.Thread(target=run, daemon=True).start()
    return int(listener.getsockname()[1])


@pytest.fixture(scope="module")
def servers(certificate: tuple[Path, Path]) -> Iterator[dict[str, int]]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        legacy = ssl.TLSVersion.TLSv1
    yield {
        "modern": _serve(certificate, ssl.TLSVersion.TLSv1_3, "DEFAULT"),
        "modern_and_legacy": _serve(certificate, ssl.TLSVersion.TLSv1_2, "DEFAULT:@SECLEVEL=0"),
        "legacy_only": _serve(certificate, legacy, "DEFAULT:@SECLEVEL=0"),
        "null_suite": _serve(certificate, ssl.TLSVersion.TLSv1_2, "ALL:eNULL:@SECLEVEL=0"),
    }


def test_a_modern_server_raises_neither_and_both_probes_complete(servers: dict[str, int]) -> None:
    info = TlsInspector().inspect("127.0.0.1", servers["modern"], timeout=3)
    assert info.legacy_accepted is False and info.weak_accepted is False
    assert not {CheckId.LEGACY_TLS_VERSION, CheckId.WEAK_TLS_CIPHER} & set(evaluate_tls(info))


def test_a_server_that_also_accepts_tls_1_0_is_caught_by_the_capped_probe(servers: dict[str, int]) -> None:
    info = TlsInspector().inspect("127.0.0.1", servers["modern_and_legacy"], timeout=3)
    assert info.version == "TLSv1.2"
    assert info.legacy_accepted is True
    assert CheckId.LEGACY_TLS_VERSION in evaluate_tls(info)


def test_a_legacy_only_server_is_read_instead_of_failing(servers: dict[str, int]) -> None:
    info = TlsInspector().inspect("127.0.0.1", servers["legacy_only"], timeout=3)
    assert info.version in ("TLSv1", "TLSv1.1") and info.not_after is not None
    assert CheckId.LEGACY_TLS_VERSION in evaluate_tls(info)


def test_a_server_that_accepts_a_null_suite_is_caught(servers: dict[str, int]) -> None:
    info = TlsInspector().inspect("127.0.0.1", servers["null_suite"], timeout=3)
    assert info.weak_accepted is True
    assert CheckId.WEAK_TLS_CIPHER in evaluate_tls(info)
