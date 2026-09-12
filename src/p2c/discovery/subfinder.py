from __future__ import annotations

import json
from datetime import datetime

from p2c.discovery.base import DiscoveryError
from p2c.discovery.normalize import assets_from_hosts, require_hostname
from p2c.discovery.runner import CommandRunner
from p2c.schemas.enums import DiscoveryMethod
from p2c.schemas.models import Asset

SUBFINDER_VERSION = "v2.14.0"


def parse_subfinder(output: str) -> list[str]:
    hosts: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        host = obj.get("host")
        if isinstance(host, str) and host:
            hosts.append(host)
    return hosts


class SubfinderSource:

    source_tool = DiscoveryMethod.SUBFINDER.value

    def __init__(
        self, runner: CommandRunner, *, version: str = SUBFINDER_VERSION, timeout: float = 120.0
    ) -> None:
        self._runner = runner
        self.version = version
        self._timeout = timeout

    def discover(self, target: str, *, consent_ref: str, now: datetime | None = None) -> list[Asset]:
        target = require_hostname(target)
        result = self._runner.run(["subfinder", "-silent", "-json", "-d", target], timeout=self._timeout)
        if result.returncode != 0:
            raise DiscoveryError(f"subfinder exited {result.returncode}: {result.stderr[:200]}")
        return assets_from_hosts(
            parse_subfinder(result.stdout),
            apex=target,
            source_tool=self.source_tool,
            tool_version=self.version,
            method=DiscoveryMethod.SUBFINDER,
            consent_ref=consent_ref,
            now=now,
        )
