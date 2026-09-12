from __future__ import annotations

from datetime import datetime

from pydantic import Field

from p2c.discovery.normalize import assets_from_hosts, normalize_host
from p2c.schemas.enums import AssetType, DiscoveryMethod
from p2c.schemas.models import Asset, AtlasModel

SYNTHETIC_VERSION = "synthetic-1"


class SyntheticAsset(AtlasModel):

    value: str
    asset_type: str = AssetType.SUBDOMAIN.value
    attributes: dict[str, object] = Field(default_factory=dict)


class SyntheticProfile(AtlasModel):

    profile_id: str
    apex: str
    assets: list[SyntheticAsset] = Field(default_factory=list)


class SyntheticSource:

    source_tool = DiscoveryMethod.SYNTHETIC.value

    def __init__(self, profile: SyntheticProfile, *, version: str = SYNTHETIC_VERSION) -> None:
        self._profile = profile
        self.version = version

    def discover(self, target: str, *, consent_ref: str, now: datetime | None = None) -> list[Asset]:
        attributes_for = {normalize_host(a.value): dict(a.attributes) for a in self._profile.assets}
        type_for = {normalize_host(a.value): a.asset_type for a in self._profile.assets}
        return assets_from_hosts(
            [a.value for a in self._profile.assets],
            apex=self._profile.apex,
            source_tool=self.source_tool,
            tool_version=self.version,
            method=DiscoveryMethod.SYNTHETIC,
            consent_ref=consent_ref,
            now=now,
            attributes_for=attributes_for,
            type_for=type_for,
        )
