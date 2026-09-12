from __future__ import annotations

from typing import Any

from p2c.schemas.models import Asset


def merge_assets(assets: list[Asset]) -> list[Asset]:
    by_value: dict[str, list[Asset]] = {}
    for asset in assets:
        by_value.setdefault(asset.value, []).append(asset)

    merged: list[Asset] = []
    for value in sorted(by_value):
        group = sorted(by_value[value], key=lambda a: a.source_tool)
        discovered_by = [
            {
                "source_tool": a.source_tool,
                "tool_version": a.tool_version,
                "discovery_method": a.discovery_method,
            }
            for a in group
        ]
        attributes: dict[str, Any] = {}
        for a in group:
            attributes.update(a.attributes)
        attributes["discovered_by"] = discovered_by
        merged.append(group[0].model_copy(update={"attributes": attributes}))
    return merged
