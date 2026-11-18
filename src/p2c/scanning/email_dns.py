from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

import structlog

from p2c.scanning.catalog import CheckId
from p2c.sovereignty.egress_guard import caused_by_egress_block

log = structlog.get_logger("p2c.scanning.email_dns")

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2")

_DEFINITIVE_ABSENCE = frozenset({"NXDOMAIN", "NoAnswer", "NoData", "DnsRecordAbsent"})


class DnsRecordAbsent(Exception):
    pass


class DnsReadIndeterminate(Exception):
    pass


class TxtResolver(Protocol):
    def resolve_txt(self, name: str) -> list[str]:
        ...


@dataclass(frozen=True)
class TxtRead:

    records: tuple[str, ...] = ()
    resolved: bool = True


@dataclass(frozen=True)
class EmailDnsResult:

    checks: tuple[CheckId, ...] = ()
    indeterminate: tuple[str, ...] = ()
    dkim_found: bool = False


def _is_definitive_absence(exc: BaseException) -> bool:
    return any(cls.__name__ in _DEFINITIVE_ABSENCE for cls in type(exc).__mro__)


def _dmarc_policy(records: tuple[str, ...]) -> str | None:
    found = [r for r in records if r.strip().lower().replace(" ", "").startswith("v=dmarc1")]
    if len(found) != 1:
        return None
    for part in found[0].split(";"):
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "p":
            return value.strip().lower()
    return None


def _spf_usable(records: tuple[str, ...]) -> bool:
    found = [r.strip() for r in records if re.match(r"(?i)v=spf1(?:\s|$)", r.strip())]
    if len(found) != 1:
        return False
    return bool(re.search(r"(?i)(?:^|\s)[-~]all(?:\s|$)|(?:^|\s)redirect=", found[0]))


_DKIM_KEY = re.compile(r"(?i)(?:^|;)\s*p\s*=\s*[^;\s]")


def _has_dkim_key(records: tuple[str, ...]) -> bool:
    return any(_DKIM_KEY.search(r) for r in records)


class EmailDnsInspector:

    def __init__(self, resolver: TxtResolver, *, selectors: tuple[str, ...] = DKIM_SELECTORS) -> None:
        self._resolver = resolver
        self._selectors = selectors

    def _txt(self, name: str) -> TxtRead:
        try:
            return TxtRead(tuple(self._resolver.resolve_txt(name)))
        except Exception as exc:
            if caused_by_egress_block(exc):
                raise
            if _is_definitive_absence(exc):
                return TxtRead()
            log.warning("dns_read_indeterminate", name=name, error=type(exc).__name__)
            return TxtRead(resolved=False)

    def inspect(self, domain: str) -> list[CheckId]:
        return list(self.inspect_detailed(domain).checks)

    def inspect_detailed(self, domain: str) -> EmailDnsResult:
        indeterminate: list[str] = []

        def read(name: str) -> TxtRead:
            result = self._txt(name)
            if not result.resolved:
                indeterminate.append(name)
            return result

        checks: list[CheckId] = []
        spf = read(domain)
        if spf.resolved and not _spf_usable(spf.records):
            checks.append(CheckId.SPF_MISSING)

        dmarc = read(f"_dmarc.{domain}")
        if dmarc.resolved:
            policy = _dmarc_policy(dmarc.records)
            if policy is None or policy == "none":
                checks.append(CheckId.DMARC_MISSING_OR_NONE)

        dkim_found = False
        dkim_fully_read = True
        for selector in self._selectors:
            probe = read(f"{selector}._domainkey.{domain}")
            dkim_fully_read = dkim_fully_read and probe.resolved
            if _has_dkim_key(probe.records):
                dkim_found = True
                break
        if not dkim_found and dkim_fully_read:
            checks.append(CheckId.DKIM_MISSING)
        return EmailDnsResult(checks=tuple(checks), indeterminate=tuple(indeterminate), dkim_found=dkim_found)
