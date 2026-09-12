from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

import structlog

from p2c.scanning.catalog import CheckId

log = structlog.get_logger("p2c.scanning.services")

_PG_SSL_REQUEST = struct.pack("!ii", 8, 80877103)
_REDIS_PING = b"PING\r\n"
_MYSQL_PROTOCOL_VERSION = 0x0A
_MIN_MYSQL_GREETING = 5


@dataclass(frozen=True)
class ServiceProbe:

    host: str
    port: int
    protocol: str | None = None
    evidence: bytes = b""
    read: bool = True


def identify_database(banner: bytes, pg_reply: bytes = b"", redis_reply: bytes = b"") -> str | None:
    if len(banner) >= _MIN_MYSQL_GREETING and banner[4] == _MYSQL_PROTOCOL_VERSION:
        return "mariadb" if b"MariaDB" in banner else "mysql"
    if pg_reply in (b"S", b"N"):
        return "postgresql"
    if redis_reply.startswith((b"+PONG", b"-NOAUTH", b"-ERR operation not permitted")):
        return "redis"
    return None


class ServiceInspector:

    def __init__(self, *, timeout: float = 5.0) -> None:
        self._timeout = timeout

    def inspect(self, host: str, port: int) -> ServiceProbe:
        try:
            banner, pg_reply, redis_reply = self._exchange(host, port)
        except OSError as exc:
            log.warning("service_read_indeterminate", host=host, port=port, error=type(exc).__name__)
            return ServiceProbe(host=host, port=port, read=False)
        protocol = identify_database(banner, pg_reply, redis_reply)
        evidence = banner or pg_reply or redis_reply
        return ServiceProbe(host=host, port=port, protocol=protocol, evidence=evidence)

    def _exchange(self, host: str, port: int) -> tuple[bytes, bytes, bytes]:
        banner = b""
        with socket.create_connection((host, port), timeout=self._timeout) as sock:
            sock.settimeout(self._timeout)
            try:
                banner = sock.recv(256)
            except TimeoutError:
                banner = b""
        if banner:
            return banner, b"", b""
        return b"", self._ask(host, port, _PG_SSL_REQUEST, 1), self._ask(host, port, _REDIS_PING, 64)

    def _ask(self, host: str, port: int, message: bytes, size: int) -> bytes:
        try:
            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                sock.settimeout(self._timeout)
                sock.sendall(message)
                return sock.recv(size)
        except OSError:
            return b""


def checks_for_service(probe: ServiceProbe) -> list[CheckId]:
    return [CheckId.EXPOSED_DATABASE_PORT] if probe.protocol else []
