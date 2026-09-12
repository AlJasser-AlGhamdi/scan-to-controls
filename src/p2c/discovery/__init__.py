from __future__ import annotations

from p2c.discovery.amass import AmassSource, parse_amass_names
from p2c.discovery.base import DiscoveryError, DiscoveryResult, DiscoverySource
from p2c.discovery.crtsh import CrtshSource, parse_crtsh
from p2c.discovery.dnsx import DnsxResolver, parse_dnsx
from p2c.discovery.engine import SYNTHETIC_EPOCH, DiscoveryEngine, synthetic_engine
from p2c.discovery.merge import merge_assets
from p2c.discovery.normalize import (
    assets_from_hosts,
    classify,
    in_scope_of,
    is_ip,
    is_valid_hostname,
    normalize_host,
    require_hostname,
    to_ascii,
    to_unicode,
)
from p2c.discovery.runner import CommandResult, CommandRunner, SubprocessRunner
from p2c.discovery.subfinder import SubfinderSource, parse_subfinder
from p2c.discovery.synthetic import SyntheticAsset, SyntheticProfile, SyntheticSource

__all__ = [
    "SYNTHETIC_EPOCH",
    "AmassSource",
    "CommandResult",
    "CommandRunner",
    "CrtshSource",
    "DiscoveryEngine",
    "DiscoveryError",
    "DiscoveryResult",
    "DiscoverySource",
    "DnsxResolver",
    "SubfinderSource",
    "SubprocessRunner",
    "SyntheticAsset",
    "SyntheticProfile",
    "SyntheticSource",
    "assets_from_hosts",
    "classify",
    "in_scope_of",
    "is_ip",
    "is_valid_hostname",
    "merge_assets",
    "normalize_host",
    "parse_amass_names",
    "parse_crtsh",
    "parse_dnsx",
    "parse_subfinder",
    "require_hostname",
    "synthetic_engine",
    "to_ascii",
    "to_unicode",
]
