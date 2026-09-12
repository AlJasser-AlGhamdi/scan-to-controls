from __future__ import annotations

import json
from dataclasses import dataclass, field

import structlog

from p2c.scanning.catalog import CheckId
from p2c.scanning.headers import analyze_security_headers

log = structlog.get_logger("p2c.scanning.httpx")


@dataclass(frozen=True)
class HttpProbe:

    url: str
    host: str
    scheme: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    tech: tuple[str, ...] = ()
    set_cookie: tuple[str, ...] = ()


def parse_httpx(output: str) -> list[HttpProbe]:
    probes: list[HttpProbe] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        url = obj.get("url")
        if not isinstance(url, str):
            continue
        raw_headers = obj.get("header") or obj.get("headers") or {}
        headers = {str(k): str(v) for k, v in raw_headers.items()} if isinstance(raw_headers, dict) else {}
        set_cookie = _set_cookie_values(raw_headers)
        raw_status = obj.get("status_code")
        status_code = raw_status if isinstance(raw_status, int) else 0
        raw_tech = obj.get("tech")
        tech = tuple(str(t) for t in raw_tech) if isinstance(raw_tech, list) else ()
        probes.append(
            HttpProbe(
                url=url,
                host=str(obj.get("host") or obj.get("input") or ""),
                scheme=str(obj.get("scheme") or (url.split("://", 1)[0] if "://" in url else "")),
                status_code=status_code,
                headers=headers,
                tech=tech,
                set_cookie=set_cookie,
            )
        )
    return probes


def _set_cookie_values(raw_headers: object) -> tuple[str, ...]:
    if not isinstance(raw_headers, dict):
        return ()
    for key, value in raw_headers.items():
        if str(key).lower() != "set-cookie":
            continue
        if isinstance(value, list):
            return tuple(str(v) for v in value)
        return tuple(part for part in str(value).splitlines() if part.strip())
    return ()


def cookie_lacks_secure(set_cookie: str) -> bool:
    attributes = {part.strip().lower() for part in set_cookie.split(";")[1:]}
    return "secure" not in attributes


_DEV_SERVER_MARKERS = ("werkzeug", "webrick", "rack-dev", "django-devserver")
_DEV_HEADERS = ("x-debug-token", "x-debug-token-link", "x-symfony-profiler")


def dev_environment_signature(headers: dict[str, str]) -> str | None:
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in _DEV_HEADERS:
            return f"{name}: {value}"
        if lowered == "server" and any(marker in value.lower() for marker in _DEV_SERVER_MARKERS):
            return f"{name}: {value}"
    return None


_REDIRECT_MIN, _REDIRECT_MAX = 300, 400
_STATUS_MIN, _STATUS_MAX = 100, 599


def response_received(probe: HttpProbe) -> bool:
    return _STATUS_MIN <= probe.status_code <= _STATUS_MAX


def _redirects_to_https(probe: HttpProbe) -> bool:
    if not (_REDIRECT_MIN <= probe.status_code < _REDIRECT_MAX):
        return False
    location = next((v for k, v in probe.headers.items() if k.lower() == "location"), "")
    return location.strip().lower().startswith("https://")


def checks_for_probe(probe: HttpProbe) -> list[CheckId]:
    if not response_received(probe):
        log.warning("http_read_indeterminate", url=probe.url, status_code=probe.status_code)
        return []
    checks: list[CheckId] = []
    if probe.scheme == "http" and not _redirects_to_https(probe):
        checks.append(CheckId.NO_HTTPS_REDIRECT)
    checks.extend(analyze_security_headers(probe.headers))
    if any(cookie_lacks_secure(value) for value in probe.set_cookie):
        checks.append(CheckId.INSECURE_COOKIE)
    if dev_environment_signature(probe.headers) is not None:
        checks.append(CheckId.EXPOSED_DEV_ENVIRONMENT)
    return checks
