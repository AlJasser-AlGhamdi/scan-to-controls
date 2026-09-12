from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

import httpx
import structlog

from p2c.scanning.catalog import CheckId
from p2c.scanning.dns_sec import RecordResolver, _is_definitive_absence
from p2c.sovereignty.egress_guard import caused_by_egress_block

log = structlog.get_logger("p2c.scanning.mta_sts")

_POLICY_URL = "https://mta-sts.{domain}/.well-known/mta-sts.txt"
_REQUIRED_FIELDS = ("version", "mode", "max_age")
_MODES = frozenset({"enforce", "testing", "none"})
_ENFORCING_MODES = frozenset({"enforce", "testing"})
_HTTP_OK = 200


class MtaStsState(StrEnum):

    RECORD_ABSENT = "record_absent"
    RECORD_MALFORMED = "record_malformed"
    POLICY_NOT_ENFORCING = "policy_not_enforcing"
    POLICY_UNREACHABLE = "policy_unreachable"
    POLICY_VALID = "policy_valid"
    UNREAD = "unread"


@dataclass(frozen=True)
class MtaStsResult:
    checks: tuple[CheckId, ...] = ()
    state: MtaStsState = MtaStsState.UNREAD
    policy: str | None = None


def _announces_policy(records: tuple[str, ...]) -> bool:
    return len(records) == 1 and records[0].strip().lower().startswith("v=stsv1")


def policy_mode(body: str) -> str | None:
    fields: dict[str, list[str]] = {}
    for line in body.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    if any(field not in fields for field in _REQUIRED_FIELDS):
        return None
    if fields["version"][0].lower() != "stsv1":
        return None
    mode = fields["mode"][0].lower()
    if mode not in _MODES or not fields["max_age"][0].isdigit():
        return None
    if mode != "none" and not fields.get("mx"):
        return None
    return mode


def parse_policy(body: str) -> bool:
    fields: dict[str, list[str]] = {}
    for line in body.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    if any(field not in fields for field in _REQUIRED_FIELDS):
        return False
    if fields["version"][0].lower() != "stsv1":
        return False
    mode = fields["mode"][0].lower()
    if mode not in _MODES:
        return False
    if not fields["max_age"][0].isdigit():
        return False
    return mode == "none" or bool(fields.get("mx"))


class MtaStsInspector:

    def __init__(self, resolver: RecordResolver, client: httpx.Client | None = None) -> None:
        self._resolver = resolver
        self._client = client

    def inspect(self, domain: str) -> list[CheckId]:
        return list(self.inspect_detailed(domain).checks)

    def inspect_detailed(self, domain: str) -> MtaStsResult:
        try:
            records = tuple(self._resolver.resolve(f"_mta-sts.{domain}", "TXT"))
        except Exception as exc:
            if caused_by_egress_block(exc):
                raise
            if not _is_definitive_absence(exc):
                log.warning("mta_sts_read_indeterminate", domain=domain, error=type(exc).__name__)
                return MtaStsResult(state=MtaStsState.UNREAD)
            records = ()
        if not records:
            return MtaStsResult(checks=(CheckId.MTA_STS_MISSING,), state=MtaStsState.RECORD_ABSENT)
        if not _announces_policy(records):
            return MtaStsResult(checks=(CheckId.MTA_STS_MISSING,), state=MtaStsState.RECORD_MALFORMED)
        return self._fetch_policy(domain)

    def _fetch_policy(self, domain: str) -> MtaStsResult:
        url = _POLICY_URL.format(domain=domain)
        try:
            if self._client is not None:
                response = self._client.get(url)
            else:
                with httpx.Client(timeout=10.0, follow_redirects=False) as client:
                    response = client.get(url)
        except Exception as exc:
            if caused_by_egress_block(exc):
                raise
            log.warning("mta_sts_policy_unreachable", domain=domain, error=type(exc).__name__)
            return MtaStsResult(state=MtaStsState.POLICY_UNREACHABLE)
        if response.status_code != _HTTP_OK:
            return MtaStsResult(state=MtaStsState.POLICY_UNREACHABLE, policy=response.text)
        mode = policy_mode(response.text)
        if mode is None:
            return MtaStsResult(state=MtaStsState.POLICY_UNREACHABLE, policy=response.text)
        if mode not in _ENFORCING_MODES:
            return MtaStsResult(
                checks=(CheckId.MTA_STS_MISSING,),
                state=MtaStsState.POLICY_NOT_ENFORCING,
                policy=response.text,
            )
        return MtaStsResult(state=MtaStsState.POLICY_VALID, policy=response.text)
