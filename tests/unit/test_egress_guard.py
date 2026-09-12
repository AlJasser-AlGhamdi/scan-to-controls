from __future__ import annotations

import socket

import pytest

from p2c.config import Settings
from p2c.sovereignty.egress_guard import (
    EgressBlocked,
    EgressPolicy,
    _host_str,
    active_policy,
    egress_guard,
    install_from_settings,
    uninstall,
)


def test_policy_allows_loopback_private_and_allowlist() -> None:
    policy = EgressPolicy(sovereign=True, allowlist=frozenset({"crt.sh"}))
    assert policy.is_allowed("127.0.0.1")
    assert policy.is_allowed("::1")
    assert policy.is_allowed("localhost")
    assert policy.is_allowed("crt.sh")
    assert policy.is_allowed("10.0.0.5")
    assert policy.is_allowed("192.168.1.1")
    assert not policy.is_allowed("example.com")
    assert not policy.is_allowed("8.8.8.8")


def test_policy_is_case_insensitive_for_allowlist() -> None:
    policy = EgressPolicy(sovereign=True, allowlist=frozenset({"crt.sh"}))
    assert policy.is_allowed("CRT.SH")


def test_policy_noop_when_not_sovereign() -> None:
    policy = EgressPolicy(sovereign=False)
    assert policy.is_allowed("example.com")
    assert policy.is_allowed("8.8.8.8")


def test_assert_allowed_raises_for_blocked_host() -> None:
    policy = EgressPolicy(sovereign=True)
    with pytest.raises(EgressBlocked):
        policy.assert_allowed("evil.example")


def test_guard_blocks_getaddrinfo_and_create_connection() -> None:
    with egress_guard(EgressPolicy(sovereign=True, allowlist=frozenset())):
        with pytest.raises(EgressBlocked):
            socket.getaddrinfo("blocked.example", 80)
        with pytest.raises(EgressBlocked):
            socket.create_connection(("blocked.example", 80), timeout=1)
        assert socket.getaddrinfo("127.0.0.1", 80)


def test_guard_blocks_direct_ip_connect() -> None:
    with egress_guard(EgressPolicy(sovereign=True, allowlist=frozenset())):
        sock = socket.socket()
        try:
            with pytest.raises(EgressBlocked):
                sock.connect(("8.8.8.8", 80))
        finally:
            sock.close()


def test_guard_uninstalled_after_context() -> None:
    with egress_guard(EgressPolicy(sovereign=True)):
        assert active_policy() is not None
    assert active_policy() is None
    assert socket.getaddrinfo("127.0.0.1", 80)


def test_allowed_loopback_egress_passes_through_guard() -> None:
    with egress_guard(EgressPolicy(sovereign=True, allowlist=frozenset())):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            client = socket.socket()
            assert client.connect_ex(("127.0.0.1", port)) == 0
            client.close()

            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.sendto(b"x", ("127.0.0.1", port))
            udp.sendmsg([b"y"], [], 0, ("127.0.0.1", port))
            udp.close()
        finally:
            listener.close()


def test_bytes_hostname_normalized_not_mangled() -> None:
    assert _host_str(b"crt.sh") == "crt.sh"
    with egress_guard(EgressPolicy(sovereign=True, allowlist=frozenset())):
        with pytest.raises(EgressBlocked):
            socket.getaddrinfo(b"blocked.example", 80)
        assert socket.getaddrinfo(b"127.0.0.1", 80)


def test_legacy_resolvers_blocked_under_sovereign_mode() -> None:
    with egress_guard(EgressPolicy(sovereign=True, allowlist=frozenset())):
        with pytest.raises(EgressBlocked):
            socket.gethostbyname("blocked.example")
        with pytest.raises(EgressBlocked):
            socket.gethostbyname_ex("blocked.example")
        with pytest.raises(EgressBlocked):
            socket.gethostbyaddr("8.8.8.8")


def test_install_from_settings_builds_policy() -> None:
    settings = Settings.model_validate({"sovereign_mode": True, "allowlisted_hosts": "a.com"})
    policy = install_from_settings(settings)
    try:
        assert active_policy() is policy
        assert policy.is_allowed("a.com")
        assert not policy.is_allowed("b.com")
    finally:
        uninstall()
