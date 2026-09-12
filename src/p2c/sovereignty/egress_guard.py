from __future__ import annotations

import asyncio
import ipaddress
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from p2c.config import Settings

log = structlog.get_logger("p2c.sovereignty")

_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "", "ip6-localhost"})
_SENDMSG_ADDR_INDEX = 3


def _normalize_host_name(host: str) -> str:
    return host.strip().rstrip(".").lower()


def _is_dangerous_ip(host: str | None) -> bool:
    if host is None:
        return False
    name = _normalize_host_name(host).split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return False
    return ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved


class EgressBlocked(OSError):
    def __init__(self, host: str) -> None:
        self.host = host
        super().__init__(
            f"SOVEREIGN_MODE: outbound connection to {host!r} is not allowlisted "
            f"(loopback/private hosts and ALLOWLISTED_HOSTS are permitted)"
        )


@dataclass(frozen=True)
class EgressPolicy:
    sovereign: bool
    allowlist: frozenset[str] = frozenset()
    allow_loopback: bool = True
    allow_private: bool = True

    def __post_init__(self) -> None:
        normalized = frozenset(_normalize_host_name(h) for h in self.allowlist if h and h.strip())
        object.__setattr__(self, "allowlist", normalized)

    def is_allowed(self, host: str | None) -> bool:
        if not self.sovereign:
            return True
        if host is None:
            return True
        name = _normalize_host_name(host)
        try:
            ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(name)
        except ValueError:
            ip = None
        if ip is not None:
            if ip.is_loopback:
                return self.allow_loopback
            if ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
                return False
            if name in self.allowlist:
                return True
            return self.allow_private if ip.is_private else False
        if name in self.allowlist:
            return True
        return self.allow_loopback if name in _LOOPBACK_NAMES else False

    def assert_allowed(self, host: str | None) -> None:
        if not self.is_allowed(host):
            resolved = host if host is not None else "<unknown>"
            log.warning("egress_blocked", host=resolved)
            raise EgressBlocked(resolved)


@dataclass
class _GuardState:
    policy: EgressPolicy | None = None
    resolved_allowlisted_ips: set[str] = field(default_factory=set)
    orig_getaddrinfo: Any = None
    orig_connect: Any = None
    orig_connect_ex: Any = None
    orig_sendto: Any = None
    orig_sendmsg: Any = None
    orig_gethostbyname: Any = None
    orig_gethostbyname_ex: Any = None
    orig_gethostbyaddr: Any = None
    orig_getnameinfo: Any = None
    installed: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


_state = _GuardState()


def _host_str(host: Any) -> str | None:
    if host is None:
        return None
    if isinstance(host, bytes | bytearray):
        try:
            return bytes(host).decode("ascii")
        except UnicodeDecodeError:
            return bytes(host).decode("utf-8", "replace")
    return str(host)


def _extract_host(address: Any) -> str | None:
    if isinstance(address, tuple) and address:
        return _host_str(address[0]) if isinstance(address[0], str | bytes | bytearray) else None
    return None


def active_policy() -> EgressPolicy | None:
    return _state.policy


def install(policy: EgressPolicy) -> None:
    with _state.lock:
        _state.resolved_allowlisted_ips.clear()
        _state.policy = policy
        if _state.installed:
            return

        real_getaddrinfo = socket.getaddrinfo
        real_connect = socket.socket.connect
        real_connect_ex = socket.socket.connect_ex
        real_sendto = socket.socket.sendto
        real_sendmsg = socket.socket.sendmsg
        real_gethostbyname = socket.gethostbyname
        real_gethostbyname_ex = socket.gethostbyname_ex
        real_gethostbyaddr = socket.gethostbyaddr
        real_getnameinfo = socket.getnameinfo

        def _check(host: str | None) -> None:
            current = _state.policy
            if current is not None:
                current.assert_allowed(host)

        def _check_connect(host: str | None) -> None:
            if host is not None and host in _state.resolved_allowlisted_ips and not _is_dangerous_ip(host):
                return
            _check(host)

        def guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
            host_str = _host_str(host)
            _check(host_str)
            result = real_getaddrinfo(host, *args, **kwargs)
            current = _state.policy
            if current is not None and host_str and _normalize_host_name(host_str) in current.allowlist:
                for entry in result:
                    sockaddr = entry[4]
                    if sockaddr and not _is_dangerous_ip(str(sockaddr[0])):
                        _state.resolved_allowlisted_ips.add(str(sockaddr[0]))
            return result

        def guarded_gethostbyname(hostname: Any) -> Any:
            _check(_host_str(hostname))
            return real_gethostbyname(hostname)

        def guarded_gethostbyname_ex(hostname: Any) -> Any:
            _check(_host_str(hostname))
            return real_gethostbyname_ex(hostname)

        def guarded_gethostbyaddr(host: Any) -> Any:
            _check(_host_str(host))
            return real_gethostbyaddr(host)

        def guarded_getnameinfo(sockaddr: Any, flags: Any) -> Any:
            _check(_extract_host(sockaddr))
            return real_getnameinfo(sockaddr, flags)

        def guarded_connect(self: socket.socket, address: Any) -> Any:
            _check_connect(_extract_host(address))
            return real_connect(self, address)

        def guarded_connect_ex(self: socket.socket, address: Any) -> Any:
            _check_connect(_extract_host(address))
            return real_connect_ex(self, address)

        def guarded_sendto(self: socket.socket, *args: Any, **kwargs: Any) -> Any:
            _check_connect(_extract_host(args[-1]) if args else None)
            return real_sendto(self, *args, **kwargs)

        def guarded_sendmsg(self: socket.socket, *args: Any, **kwargs: Any) -> Any:
            positional = args[_SENDMSG_ADDR_INDEX] if len(args) > _SENDMSG_ADDR_INDEX else None
            address = kwargs.get("address", positional)
            if address is not None:
                _check_connect(_extract_host(address))
            return real_sendmsg(self, *args, **kwargs)

        _state.orig_getaddrinfo = real_getaddrinfo
        _state.orig_connect = real_connect
        _state.orig_connect_ex = real_connect_ex
        _state.orig_sendto = real_sendto
        _state.orig_sendmsg = real_sendmsg
        _state.orig_gethostbyname = real_gethostbyname
        _state.orig_gethostbyname_ex = real_gethostbyname_ex
        _state.orig_gethostbyaddr = real_gethostbyaddr
        _state.orig_getnameinfo = real_getnameinfo
        socket.getaddrinfo = guarded_getaddrinfo
        socket.gethostbyname = guarded_gethostbyname
        socket.gethostbyname_ex = guarded_gethostbyname_ex
        socket.gethostbyaddr = guarded_gethostbyaddr
        socket.getnameinfo = guarded_getnameinfo
        socket.socket.connect = guarded_connect
        socket.socket.connect_ex = guarded_connect_ex
        socket.socket.sendto = guarded_sendto
        socket.socket.sendmsg = guarded_sendmsg
        _state.installed = True
        log.info(
            "egress_guard_installed",
            sovereign=policy.sovereign,
            allowlist=sorted(policy.allowlist),
        )


def uninstall() -> None:
    with _state.lock:
        if not _state.installed:
            _state.policy = None
            return
        socket.getaddrinfo = _state.orig_getaddrinfo
        socket.gethostbyname = _state.orig_gethostbyname
        socket.gethostbyname_ex = _state.orig_gethostbyname_ex
        socket.gethostbyaddr = _state.orig_gethostbyaddr
        socket.getnameinfo = _state.orig_getnameinfo
        socket.socket.connect = _state.orig_connect
        socket.socket.connect_ex = _state.orig_connect_ex
        socket.socket.sendto = _state.orig_sendto
        socket.socket.sendmsg = _state.orig_sendmsg
        _state.installed = False
        _state.policy = None
        _state.resolved_allowlisted_ips = set()


def caused_by_egress_block(exc: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, EgressBlocked):
            return True
        current = current.__cause__ or current.__context__
    return False


def running_loop_is_guarded() -> bool:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return True
    return not type(loop).__module__.startswith("uvloop")


def install_from_settings(settings: Settings) -> EgressPolicy:
    policy = EgressPolicy(sovereign=settings.sovereign_mode, allowlist=settings.allowlisted_hosts)
    install(policy)
    return policy


@contextmanager
def egress_guard(policy: EgressPolicy) -> Iterator[EgressPolicy]:
    prev_policy = _state.policy
    prev_installed = _state.installed
    install(policy)
    try:
        yield policy
    finally:
        if not prev_installed:
            uninstall()
        elif prev_policy is not None:
            _state.policy = prev_policy
