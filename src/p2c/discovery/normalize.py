from __future__ import annotations

from datetime import UTC, datetime

from p2c.hosts import (
    _clean,
    canonical_host,
    in_scope_of,
    is_ip,
    is_valid_hostname,
    normalize_host,
    require_hostname,
    to_ascii,
    to_unicode,
)
from p2c.schemas.enums import AssetType, DiscoveryMethod
from p2c.schemas.models import Asset

__all__ = [
    "assets_from_hosts",
    "canonical_host",
    "classify",
    "in_scope_of",
    "is_ip",
    "is_valid_hostname",
    "normalize_host",
    "require_hostname",
    "to_ascii",
    "to_unicode",
]


def classify(value: str, apex: str) -> AssetType:
    if is_ip(value):
        return AssetType.IP
    return AssetType.DOMAIN if normalize_host(value) == normalize_host(apex) else AssetType.SUBDOMAIN


def _utcnow() -> datetime:
    return datetime.now(UTC)


def assets_from_hosts(
    hosts: list[str],
    *,
    apex: str,
    source_tool: str,
    tool_version: str,
    method: DiscoveryMethod,
    consent_ref: str,
    now: datetime | None = None,
    attributes_for: dict[str, dict[str, object]] | None = None,
    type_for: dict[str, str] | None = None,
) -> list[Asset]:
    stamp = now or _utcnow()
    seen: set[str] = set()
    assets: list[Asset] = []
    for raw in hosts:
        cleaned = _clean(raw)
        value = to_ascii(cleaned)
        if not value or value in seen or not in_scope_of(value, apex):
            continue
        if not (is_valid_hostname(value) or is_ip(value)):
            continue
        seen.add(value)
        extra = dict((attributes_for or {}).get(value, {}))
        if cleaned and cleaned != value:
            extra.setdefault("unicode_host", cleaned)
        asset_type = (type_for or {}).get(value) or classify(value, apex).value
        assets.append(
            Asset(
                asset_id=value,
                value=value,
                asset_type=asset_type,
                source_tool=source_tool,
                tool_version=tool_version,
                discovery_method=method.value,
                consent_ref=consent_ref,
                first_seen=stamp,
                attributes=extra,
            )
        )
    return sorted(assets, key=lambda a: a.value)
