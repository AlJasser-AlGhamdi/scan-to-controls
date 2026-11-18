from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass

import structlog

from p2c.scanning.catalog import CheckId
from p2c.scanning.dns_sec import RecordResolver, _is_definitive_absence
from p2c.sovereignty.egress_guard import caused_by_egress_block

log = structlog.get_logger("p2c.scanning.dns_axfr")

Transfer = Callable[[str, str, int], list[str]]
_REFUSALS = frozenset({"TransferError", "ConnectionRefusedError", "ConnectionResetError", "EOFError"})


_MAX_NAMES = 2


def dnspython_transfer(address: str, zone: str, port: int, *, timeout: float = 10.0) -> list[str]:
    import dns.name
    import dns.query

    origin = dns.name.from_text(zone)
    names: dict[str, None] = {}
    for message in dns.query.xfr(address, zone, port=port, timeout=timeout, lifetime=timeout):
        for rrset in message.answer:
            names[rrset.name.relativize(origin).to_text()] = None
            if len(names) >= _MAX_NAMES:
                return list(names)
    return list(names)


_EMBEDDED_V4 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("::/96"))


def _internal(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv6Address) and any(ip in net for net in _EMBEDDED_V4):
        return True
    return not ip.is_global or ip.is_multicast


def _refused(exc: BaseException) -> bool:
    return any(cls.__name__ in _REFUSALS for cls in type(exc).__mro__)


@dataclass(frozen=True)
class AxfrResult:
    checks: tuple[CheckId, ...] = ()
    read: bool = False
    server: str | None = None
    n_names: int = 0


class ZoneTransferInspector:

    def __init__(
        self,
        resolver: RecordResolver,
        transfer: Transfer | None = None,
        *,
        port: int = 53,
        allow_internal: bool = False,
        address_types: tuple[str, ...] = ("A", "AAAA"),
    ) -> None:
        self._resolver = resolver
        self._address_types = address_types
        self._transfer = transfer or dnspython_transfer
        self._port = port
        self._allow_internal = allow_internal

    def inspect_detailed(self, domain: str) -> AxfrResult:
        try:
            servers = [s.rstrip(".") for s in self._resolver.resolve(domain, "NS")]
        except Exception as exc:
            if caused_by_egress_block(exc):
                raise
            if _is_definitive_absence(exc):
                return AxfrResult(read=True)
            log.warning("axfr_ns_read_indeterminate", domain=domain, error=type(exc).__name__)
            return AxfrResult()
        refused_all = bool(servers)
        for server in servers:
            refused = False
            for address in self._addresses(server):
                if not self._allow_internal and _internal(address):
                    log.warning("axfr_internal_address_skipped", server=server, address=address)
                    continue
                try:
                    names = self._transfer(address, domain, self._port)
                except Exception as exc:
                    if caused_by_egress_block(exc):
                        raise
                    if _refused(exc):
                        refused = True
                        break
                    log.warning("axfr_read_indeterminate", server=server, error=type(exc).__name__)
                    continue
                beyond_apex = [n for n in names if n not in ("@", "")]
                if beyond_apex:
                    return AxfrResult(
                        checks=(CheckId.DNS_ZONE_TRANSFER_OPEN,),
                        read=True,
                        server=server,
                        n_names=len(names),
                    )
                break
            refused_all = refused_all and refused
        return AxfrResult(read=True) if refused_all else AxfrResult()

    def _addresses(self, server: str) -> list[str]:
        found: list[str] = []
        for rdtype in self._address_types:
            try:
                found += self._resolver.resolve(server, rdtype)
            except Exception as exc:
                if caused_by_egress_block(exc):
                    raise
        return found

    def inspect(self, domain: str) -> list[CheckId]:
        return list(self.inspect_detailed(domain).checks)
