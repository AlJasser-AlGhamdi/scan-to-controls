from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import structlog

from p2c.scanning.catalog import CheckId
from p2c.sovereignty.egress_guard import caused_by_egress_block

log = structlog.get_logger("p2c.scanning.dns_sec")

_DEFINITIVE_ABSENCE = frozenset({"NXDOMAIN", "NoAnswer", "NoData", "DnsRecordAbsent"})


class RecordResolver(Protocol):
    def resolve(self, name: str, rdtype: str) -> list[str]:
        ...


@dataclass(frozen=True)
class RecordRead:

    records: tuple[str, ...] = ()
    resolved: bool = True


class DnspythonResolver:
    def __init__(self, *, timeout: float = 5.0) -> None:
        self._timeout = timeout

    def resolve(self, name: str, rdtype: str) -> list[str]:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self._timeout
        answer = resolver.resolve(name, rdtype)
        return [record.to_text() for record in answer]


@dataclass(frozen=True)
class DnssecResult:

    checks: tuple[CheckId, ...] = ()
    ds: RecordRead = RecordRead(resolved=False)
    dnskey: RecordRead = RecordRead(resolved=False)

    @property
    def fully_read(self) -> bool:
        return self.ds.resolved and self.dnskey.resolved


def _is_definitive_absence(exc: BaseException) -> bool:
    return any(cls.__name__ in _DEFINITIVE_ABSENCE for cls in type(exc).__mro__)


class DnssecInspector:

    def __init__(self, resolver: RecordResolver) -> None:
        self._resolver = resolver

    def inspect(self, domain: str) -> list[CheckId]:
        return list(self.inspect_detailed(domain).checks)

    def inspect_detailed(self, domain: str) -> DnssecResult:
        ds = self._read(domain, "DS")
        dnskey = self._read(domain, "DNSKEY")
        signed = bool(ds.records) or bool(dnskey.records)
        unsigned = ds.resolved and dnskey.resolved and not signed
        checks = (CheckId.DNSSEC_MISSING,) if unsigned else ()
        return DnssecResult(checks=checks, ds=ds, dnskey=dnskey)

    def _read(self, name: str, rdtype: str) -> RecordRead:
        try:
            return RecordRead(tuple(self._resolver.resolve(name, rdtype)))
        except Exception as exc:
            if caused_by_egress_block(exc):
                raise
            if _is_definitive_absence(exc):
                return RecordRead()
            log.warning("dns_read_indeterminate", name=name, rdtype=rdtype, error=type(exc).__name__)
            return RecordRead(resolved=False)
