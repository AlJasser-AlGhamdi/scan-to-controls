from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

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

    def __init__(self, *, timeout: float = 5.0, nameservers: list[str] | None = None, port: int = 53) -> None:
        self._timeout = timeout
        self._nameservers = nameservers
        self._port = port

    def resolve(self, name: str, rdtype: str) -> list[str]:
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=self._nameservers is None)
        if self._nameservers is not None:
            resolver.nameservers = self._nameservers
            resolver.port = self._port
        resolver.lifetime = self._timeout
        answer = resolver.resolve(name, rdtype)
        return [record.to_text() for record in answer]

    def resolve_txt(self, name: str) -> list[str]:
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=self._nameservers is None)
        if self._nameservers is not None:
            resolver.nameservers = self._nameservers
            resolver.port = self._port
        resolver.lifetime = self._timeout
        answer = resolver.resolve(name, "TXT")
        return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]

    def dnskey_rrsets(self, name: str) -> tuple[Any, Any]:
        return self.signed_rrset(name, "DNSKEY")

    def signed_rrset(self, name: str, rdtype: str) -> tuple[Any, Any]:
        import dns.flags
        import dns.rdataclass
        import dns.rdatatype
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=self._nameservers is None)
        if self._nameservers is not None:
            resolver.nameservers = self._nameservers
            resolver.port = self._port
        resolver.lifetime = self._timeout
        resolver.use_edns(0, dns.flags.DO, 1232)
        answer = resolver.resolve(name, rdtype)
        records = answer.rrset
        if records is None:
            return None, None
        covered = dns.rdatatype.from_text(rdtype)
        sigs = answer.response.get_rrset(
            answer.response.answer, records.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, covered
        )
        return records, sigs


def chain_verifies(
    ds_records: Sequence[str],
    keys: Any,
    sigs: Any,
    *,
    soa: Any = None,
    soa_sigs: Any = None,
    now: float | None = None,
) -> bool:
    import dns.dnssec
    import dns.exception
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype
    import dns.rrset

    if keys is None or sigs is None:
        return False
    try:
        delegated = [dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, t) for t in ds_records]
    except dns.exception.DNSException:
        return False
    matched: list[Any] = []
    for key in keys:
        for ds in delegated:
            try:
                digest_type = getattr(ds, "digest_type", None)
                if digest_type is not None and dns.dnssec.make_ds(
                    keys.name, key, digest_type, validating=True
                ) == ds:
                    matched.append(key)
                    break
            except (dns.exception.DNSException, ValueError):
                continue
    if not matched:
        return False
    trusted = dns.rrset.from_rdata_list(keys.name, keys.ttl, matched)
    try:
        dns.dnssec.validate(keys, sigs, {keys.name: trusted}, now=now)
        if soa is not None:
            if soa_sigs is None:
                return False
            dns.dnssec.validate(soa, soa_sigs, {keys.name: keys}, now=now)
    except (dns.exception.DNSException, ValueError):
        return False
    return True


@dataclass(frozen=True)
class DnssecResult:

    checks: tuple[CheckId, ...] = ()
    ds: RecordRead = RecordRead(resolved=False)
    dnskey: RecordRead = RecordRead(resolved=False)
    broken: bool = False

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
        broken = bool(ds.records) and dnskey.resolved and not dnskey.records
        return DnssecResult(checks=checks, ds=ds, dnskey=dnskey, broken=broken)

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
