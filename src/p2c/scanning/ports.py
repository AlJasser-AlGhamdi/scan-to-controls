from __future__ import annotations

import json

from p2c.scanning.catalog import CheckId

_INTERNAL_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017}
_MANAGEMENT_PORTS = {22, 3389, 5900, 5985, 5986}
_HIGH_RISK_PORTS = {21, 23, 25, 111, 135, 139, 445, 512, 513, 514}


def parse_naabu(output: str) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        host = obj.get("host") or obj.get("ip")
        port = obj.get("port")
        if isinstance(host, str) and isinstance(port, int):
            results.append((host, port))
    return results


def classify_port(port: int) -> CheckId | None:
    if port in _INTERNAL_PORTS:
        return CheckId.EXPOSED_INTERNAL_PORT
    if port in _MANAGEMENT_PORTS:
        return CheckId.EXPOSED_MANAGEMENT_PORT
    if port in _HIGH_RISK_PORTS:
        return CheckId.HIGH_RISK_PORT_OPEN
    return None
