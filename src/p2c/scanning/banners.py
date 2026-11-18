from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from functools import cache
from pathlib import Path

import structlog

from p2c.scanning.catalog import CheckId
from p2c.scanning.httpx_probe import HttpProbe, response_received

log = structlog.get_logger("p2c.scanning.banners")

_SNAPSHOT = Path(__file__).parent / "data" / "lifecycle.json"
_PRODUCTS: dict[str, str] = {"nginx": "nginx", "apache": "apache-http-server", "php": "php"}
_TOKEN = re.compile(r"(?i)\b(nginx|apache|php)/(\d{1,6}(?:\.\d{1,6}){1,3})\b")
_BANNER_HEADERS = ("server", "x-powered-by")
_BARE = re.compile(r"(?i)\b(nginx|apache|php)\b(?!/\d)")
_DISTRO = re.compile(
    r"(?i)\((?:ubuntu|debian|raspbian|red hat[^)]*|centos[^)]*|rocky[^)]*|almalinux[^)]*|fedora[^)]*"
    r"|suse[^)]*|opensuse[^)]*|amazon[^)]*|oracle[^)]*|alpine[^)]*)\)"
    r"|[-+~.]\d*(?:deb\d|ubuntu|el\d|fc\d|amzn)"
)
_COMMENT = re.compile(r"\([^)]*\)")
_SEPARATORS = re.compile(r"[\s,;]+")
_STALE_AFTER_DAYS = 180
PATCH_WINDOW_DAYS = 92


class BannerState(StrEnum):
    READ = "read"
    NO_RESPONSE = "no_response"
    NO_BANNER = "no_banner"
    UNCOVERED = "uncovered"


@dataclass(frozen=True)
class BannerToken:
    header: str
    product: str
    version: str
    cycle: str | None = None
    latest: str | None = None
    eol: str | bool | None = None
    missed: str | None = None


@dataclass(frozen=True)
class BannerResult:
    checks: tuple[CheckId, ...] = ()
    state: BannerState = BannerState.NO_RESPONSE
    tokens: tuple[BannerToken, ...] = field(default_factory=tuple)
    unread: tuple[CheckId, ...] = ()


@cache
def lifecycle_snapshot() -> dict[str, list[dict[str, object]]]:
    doc = json.loads(_SNAPSHOT.read_text(encoding="utf-8"))
    products: dict[str, list[dict[str, object]]] = doc["products"]
    return products


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _cycle_for(product: str, version: str) -> dict[str, object] | None:
    parts = _version_tuple(version)
    best: dict[str, object] | None = None
    best_len = 0
    for entry in lifecycle_snapshot().get(product, []):
        cycle = _version_tuple(str(entry["cycle"]))
        if parts[: len(cycle)] == cycle and len(cycle) > best_len:
            best, best_len = entry, len(cycle)
    return best


def _first_missed(entry: dict[str, object], version: str) -> str | None:
    patches = entry.get("patches")
    if not isinstance(patches, dict):
        return None
    mine = _version_tuple(version)
    newer = [(_version_tuple(name), day) for name, day in patches.items() if _version_tuple(name) > mine]
    return min(newer)[1] if newer else None


def _ended(eol: object, today: date) -> bool:
    if eol is True:
        return True
    if isinstance(eol, str):
        return date.fromisoformat(eol) <= today
    return False


def banner_tokens(headers: dict[str, str]) -> list[BannerToken]:
    tokens: list[BannerToken] = []
    for name, value in headers.items():
        if name.lower() not in _BANNER_HEADERS:
            continue
        for match in _TOKEN.finditer(value):
            product = _PRODUCTS[match.group(1).lower()]
            tokens.append(BannerToken(header=name, product=product, version=match.group(2)))
    return tokens


def _bare_products(headers: dict[str, str]) -> bool:
    return any(_BARE.search(value) for name, value in headers.items() if name.lower() in _BANNER_HEADERS)


def _other_products(headers: dict[str, str]) -> bool:
    banners = [value for name, value in headers.items() if name.lower() in _BANNER_HEADERS]
    if not any(name.lower() == "server" for name in headers):
        return True
    words = (w for value in banners for w in _SEPARATORS.split(_COMMENT.sub(" ", value)))
    return any(w[:1].isalpha() and w.split("/", 1)[0].lower() not in _PRODUCTS for w in words)


def snapshot_retrieved() -> date:
    return date.fromisoformat(json.loads(_SNAPSHOT.read_text(encoding="utf-8"))["retrieved"])


def snapshot_is_stale(today: date) -> bool:
    return (today - snapshot_retrieved()).days > _STALE_AFTER_DAYS


def evaluate_banners(headers: dict[str, str], *, today: date) -> BannerResult:
    if snapshot_is_stale(today):
        log.warning("lifecycle_snapshot_stale", scan_date=today.isoformat())
    tokens = banner_tokens(headers)
    if not tokens:
        return BannerResult(state=BannerState.NO_BANNER)
    if any(_DISTRO.search(v) for k, v in headers.items() if k.lower() in _BANNER_HEADERS):
        return BannerResult(state=BannerState.UNCOVERED, tokens=tuple(tokens))
    assessed: list[BannerToken] = []
    checks: set[CheckId] = set()
    uncovered = unplaced = _other_products(headers)
    ended = False
    for token in tokens:
        entry = _cycle_for(token.product, token.version)
        if entry is None:
            uncovered = unplaced = True
            assessed.append(token)
            continue
        cycle, latest, eol = str(entry["cycle"]), str(entry["latest"]), entry["eol"]
        missed: str | None = None
        if _ended(eol, today):
            checks.add(CheckId.EOL_SOFTWARE_EXPOSED)
            ended = True
        elif len(_version_tuple(token.version)) <= len(_version_tuple(cycle)):
            uncovered = True
        elif _version_tuple(token.version) < _version_tuple(latest):
            missed = _first_missed(entry, token.version)
            uncovered |= missed is None
            if missed and (today - date.fromisoformat(missed)).days > PATCH_WINDOW_DAYS:
                checks.add(CheckId.OUTDATED_EXPOSED_SOFTWARE)
        assessed.append(
            BannerToken(token.header, token.product, token.version, cycle, latest, eol, missed)
        )
    if checks:
        bare = _bare_products(headers)
        open_checks = [
            check
            for check, unknown in (
                (CheckId.OUTDATED_EXPOSED_SOFTWARE, uncovered or ended or bare),
                (CheckId.EOL_SOFTWARE_EXPOSED, unplaced or bare),
            )
            if unknown and check not in checks
        ]
        return BannerResult(
            checks=tuple(sorted(checks)),
            state=BannerState.READ,
            tokens=tuple(assessed),
            unread=tuple(open_checks),
        )
    if uncovered:
        return BannerResult(state=BannerState.UNCOVERED, tokens=tuple(assessed))
    if _bare_products(headers):
        return BannerResult(state=BannerState.NO_BANNER, tokens=tuple(assessed))
    return BannerResult(state=BannerState.READ, tokens=tuple(assessed))


def banner_checks(probe: HttpProbe, *, today: date) -> list[CheckId]:
    if not response_received(probe):
        log.warning("banner_read_indeterminate", url=probe.url, status_code=probe.status_code)
        return []
    return list(evaluate_banners(probe.headers, today=today).checks)
