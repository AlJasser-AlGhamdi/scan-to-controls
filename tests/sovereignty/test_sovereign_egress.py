from __future__ import annotations

import asyncio
import socket

import httpx
import pytest

from p2c.sovereignty.egress_guard import EgressBlocked, EgressPolicy, egress_guard

pytestmark = pytest.mark.sovereignty

_SOVEREIGN = EgressPolicy(sovereign=True, allowlist=frozenset())


def _chain_contains(exc: BaseException, exc_type: type[BaseException]) -> bool:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, exc_type):
            return True
        current = current.__cause__ or current.__context__
    return False


def test_socket_egress_blocked_under_sovereign_mode() -> None:
    with (
        egress_guard(EgressPolicy(sovereign=True, allowlist=frozenset())),
        pytest.raises(EgressBlocked),
    ):
        socket.getaddrinfo("non-allowlisted.example", 443)


def test_allowlisted_host_permitted_at_policy_level() -> None:
    policy = EgressPolicy(sovereign=True, allowlist=frozenset({"allowed.example"}))
    assert policy.is_allowed("allowed.example")
    assert not policy.is_allowed("non-allowlisted.example")


def test_httpx_request_blocked_under_sovereign_mode() -> None:
    with (
        egress_guard(_SOVEREIGN),
        pytest.raises(httpx.HTTPError) as excinfo,
    ):
        httpx.get("http://non-allowlisted.example/", timeout=2.0)
    assert _chain_contains(excinfo.value, EgressBlocked)


def test_udp_sendto_blocked_under_sovereign_mode() -> None:
    with egress_guard(_SOVEREIGN):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(EgressBlocked):
                sock.sendto(b"\x00\x01", ("8.8.8.8", 53))
        finally:
            sock.close()


def test_udp_sendmsg_blocked_under_sovereign_mode() -> None:
    with egress_guard(_SOVEREIGN):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(EgressBlocked):
                sock.sendmsg([b"\x00\x01"], [], 0, ("8.8.8.8", 53))
        finally:
            sock.close()


def test_connect_ex_blocked_under_sovereign_mode() -> None:
    with egress_guard(_SOVEREIGN):
        sock = socket.socket()
        try:
            with pytest.raises(EgressBlocked):
                sock.connect_ex(("8.8.8.8", 80))
        finally:
            sock.close()


async def test_async_selector_loop_egress_blocked() -> None:
    with egress_guard(_SOVEREIGN), pytest.raises((EgressBlocked, OSError)) as excinfo:
        await asyncio.open_connection("8.8.8.8", 80)
    assert _chain_contains(excinfo.value, EgressBlocked)


def test_allowlisted_and_loopback_permitted_under_guard() -> None:
    policy = EgressPolicy(sovereign=True, allowlist=frozenset({"allowed.example"}))
    with egress_guard(policy):
        assert socket.getaddrinfo("127.0.0.1", 80)
    assert policy.is_allowed("allowed.example")
