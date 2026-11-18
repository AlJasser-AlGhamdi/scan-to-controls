from __future__ import annotations

import re
import time
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
_ENFORCING_MODES = frozenset({"enforce"})
_HTTP_OK = 200
_MAX_POLICY_BYTES = 65_536
_MAX_POLICY_SECONDS = 30.0


def _get_capped(client: httpx.Client, url: str) -> tuple[int, str] | None:
    deadline = time.monotonic() + _MAX_POLICY_SECONDS
    with client.stream("GET", url, headers={"Accept-Encoding": "identity"}) as response:
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > _MAX_POLICY_BYTES:
                return None
            if time.monotonic() > deadline:
                raise httpx.ReadTimeout(f"the policy took longer than {_MAX_POLICY_SECONDS:.0f} seconds")
        return response.status_code, body.decode("utf-8", "replace")


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


_STS_ID = re.compile(r"(?:^|;)\s*id=[A-Za-z0-9]{1,32}\s*(?:;|$)")


def _announces_policy(records: tuple[str, ...]) -> bool:
    sts = [r for r in records if r.strip().lower().startswith("v=stsv1")]
    return len(sts) == 1 and bool(_STS_ID.search(sts[0]))


_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _txt_text(record: str) -> str:
    parts = _QUOTED.findall(record)
    return "".join(parts) if parts and record.lstrip().startswith('"') else record


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
        name = f"_mta-sts.{domain}"
        try:
            read = getattr(self._resolver, "resolve_txt", None)
            raw = read(name) if read else [_txt_text(r) for r in self._resolver.resolve(name, "TXT")]
            records = tuple(raw)
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
                fetched = _get_capped(self._client, url)
            else:
                with httpx.Client(timeout=10.0, follow_redirects=False, trust_env=False) as client:
                    fetched = _get_capped(client, url)
        except Exception as exc:
            if caused_by_egress_block(exc):
                raise
            log.warning("mta_sts_policy_unreachable", domain=domain, error=type(exc).__name__)
            return MtaStsResult(state=MtaStsState.POLICY_UNREACHABLE)
        if fetched is None:
            log.warning("mta_sts_policy_oversized", domain=domain, limit=_MAX_POLICY_BYTES)
            return MtaStsResult(state=MtaStsState.POLICY_UNREACHABLE)
        status, text = fetched
        if status != _HTTP_OK:
            return MtaStsResult(state=MtaStsState.POLICY_UNREACHABLE, policy=text)
        mode = policy_mode(text)
        if mode is None:
            return MtaStsResult(state=MtaStsState.POLICY_UNREACHABLE, policy=text)
        if mode not in _ENFORCING_MODES:
            return MtaStsResult(
                checks=(CheckId.MTA_STS_MISSING,),
                state=MtaStsState.POLICY_NOT_ENFORCING,
                policy=text,
            )
        return MtaStsResult(state=MtaStsState.POLICY_VALID, policy=text)
