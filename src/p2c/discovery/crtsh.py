from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime

import httpx

from p2c.discovery.base import DiscoveryError
from p2c.discovery.normalize import assets_from_hosts, require_hostname
from p2c.hosts import is_ip
from p2c.schemas.enums import DiscoveryMethod
from p2c.schemas.models import Asset

CRTSH_HOST = "crt.sh"
CRTSH_VERSION = "crt.sh-json"
_TIMEOUT = 30.0


def parse_crtsh(output: str) -> list[str]:
    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        raise DiscoveryError(f"crt.sh response was not JSON: {output[:80]!r}") from exc
    if not isinstance(data, list):
        raise DiscoveryError(f"crt.sh JSON was not a list: {type(data).__name__}")
    hosts: list[str] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        names = str(entry.get("name_value", "")).split("\n")
        names.append(str(entry.get("common_name", "")))
        hosts.extend(name.strip() for name in names if name.strip() and not is_ip(name.strip()))
    return hosts


class CrtshSource:

    source_tool = DiscoveryMethod.CRTSH.value

    def __init__(
        self,
        *,
        client_factory: Callable[[], httpx.Client] = httpx.Client,
        base_url: str = "https://crt.sh",
        version: str = CRTSH_VERSION,
        timeout: float = _TIMEOUT,
    ) -> None:
        self._client_factory = client_factory
        self._base_url = base_url.rstrip("/")
        self.version = version
        self._timeout = timeout

    def discover(self, target: str, *, consent_ref: str, now: datetime | None = None) -> list[Asset]:
        target = require_hostname(target)
        with self._client_factory() as client:
            response = client.get(
                f"{self._base_url}/",
                params={"q": f"%.{target}", "output": "json"},
                timeout=self._timeout,
            )
        if response.status_code != httpx.codes.OK:
            raise DiscoveryError(f"crt.sh returned HTTP {response.status_code} for {target!r}")
        return assets_from_hosts(
            parse_crtsh(response.text),
            apex=target,
            source_tool=self.source_tool,
            tool_version=self.version,
            method=DiscoveryMethod.CRTSH,
            consent_ref=consent_ref,
            now=now,
        )
