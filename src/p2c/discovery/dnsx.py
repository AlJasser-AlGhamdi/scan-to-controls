from __future__ import annotations

import json

from p2c.discovery.base import DiscoveryError
from p2c.discovery.normalize import normalize_host
from p2c.discovery.runner import CommandRunner
from p2c.schemas.enums import AssetType, DiscoveryMethod
from p2c.schemas.models import Asset

DNSX_VERSION = "v1.2.3"
_RESOLVABLE_TYPES = {AssetType.DOMAIN.value, AssetType.SUBDOMAIN.value}


def parse_dnsx(output: str) -> dict[str, dict[str, object]]:
    resolutions: dict[str, dict[str, object]] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        host = obj.get("host")
        if not isinstance(host, str) or not host:
            continue
        record = {key: obj[key] for key in ("a", "aaaa", "cname") if obj.get(key)}
        resolutions[normalize_host(host)] = record
    return resolutions


class DnsxResolver:

    source_tool = DiscoveryMethod.DNSX.value

    def __init__(self, runner: CommandRunner, *, version: str = DNSX_VERSION, timeout: float = 120.0) -> None:
        self._runner = runner
        self.version = version
        self._timeout = timeout

    def resolve(self, assets: list[Asset]) -> list[Asset]:
        hosts = [a.value for a in assets if a.asset_type in _RESOLVABLE_TYPES]
        if not hosts:
            return assets
        result = self._runner.run(
            ["dnsx", "-silent", "-json", "-resp", "-a", "-aaaa", "-cname"],
            stdin="\n".join(hosts),
            timeout=self._timeout,
        )
        if result.returncode != 0:
            raise DiscoveryError(f"dnsx exited {result.returncode}: {result.stderr[:200]}")
        resolutions = parse_dnsx(result.stdout)
        annotated: list[Asset] = []
        for asset in assets:
            if asset.asset_type not in _RESOLVABLE_TYPES:
                annotated.append(asset)
                continue
            record = resolutions.get(asset.value, {})
            annotated.append(
                asset.model_copy(
                    update={"attributes": {**asset.attributes, "dns": record, "resolved": bool(record)}}
                )
            )
        return annotated
