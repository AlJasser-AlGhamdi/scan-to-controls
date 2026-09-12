from __future__ import annotations

import tempfile
from datetime import datetime

from p2c.discovery.normalize import assets_from_hosts, require_hostname
from p2c.discovery.runner import CommandRunner
from p2c.schemas.enums import DiscoveryMethod
from p2c.schemas.models import Asset

AMASS_VERSION = "v5.1.1"


def parse_amass_names(output: str) -> list[str]:
    return [line.strip() for line in output.splitlines() if line.strip()]


class AmassSource:

    source_tool = DiscoveryMethod.AMASS_PASSIVE.value

    def __init__(
        self, runner: CommandRunner, *, version: str = AMASS_VERSION, timeout: float = 300.0
    ) -> None:
        self._runner = runner
        self.version = version
        self._timeout = timeout

    def discover(self, target: str, *, consent_ref: str, now: datetime | None = None) -> list[Asset]:
        target = require_hostname(target)
        with tempfile.TemporaryDirectory(prefix="atlas-amass-") as db_dir:
            self._runner.run(
                ["amass", "enum", "-passive", "-nocolor", "-d", target, "-dir", db_dir],
                timeout=self._timeout,
            )
            result = self._runner.run(
                ["amass", "subs", "-names", "-nocolor", "-d", target, "-dir", db_dir],
                timeout=self._timeout,
            )
        return assets_from_hosts(
            parse_amass_names(result.stdout),
            apex=target,
            source_tool=self.source_tool,
            tool_version=self.version,
            method=DiscoveryMethod.AMASS_PASSIVE,
            consent_ref=consent_ref,
            now=now,
        )
