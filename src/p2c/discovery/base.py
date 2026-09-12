from __future__ import annotations

from datetime import datetime
from typing import Protocol

from pydantic import Field, computed_field

from p2c.schemas.models import Asset, AtlasModel


class DiscoveryError(RuntimeError):
    pass
class DiscoverySource(Protocol):

    source_tool: str

    def discover(self, target: str, *, consent_ref: str, now: datetime | None = None) -> list[Asset]: ...


class DiscoveryResult(AtlasModel):

    target: str
    assets: list[Asset]
    sources: list[str] = Field(description="source_tools that were run")
    errors: list[str] = Field(default_factory=list)

    @computed_field
    @property
    def asset_count(self) -> int:
        return len(self.assets)
