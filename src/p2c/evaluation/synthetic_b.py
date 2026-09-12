from __future__ import annotations

import random

from p2c.config import get_settings
from p2c.discovery.synthetic import SyntheticAsset, SyntheticProfile
from p2c.evaluation.synthetic import (
    _APEX_CATEGORIES,
    _HOST_CATEGORIES,
    CATEGORIES,
    EvalCase,
    GroundTruth,
    InjectedFinding,
    _attestations,
    _control_ids_for,
    _dedup,
    _draw_conditions,
    _observe,
    draw_off_surface_evidence,
    expert_key,
)
from p2c.scanning.catalog import CheckId
from p2c.schemas.enums import AssetType

_SEED_OFFSET_B = 770_000

BASE_PREVALENCE: dict[CheckId, float] = {
    CheckId.MISSING_HSTS: 0.80,
    CheckId.MISSING_CSP: 0.75,
    CheckId.MISSING_X_FRAME_OPTIONS: 0.70,
    CheckId.MISSING_X_CONTENT_TYPE_OPTIONS: 0.65,
    CheckId.MISSING_REFERRER_POLICY: 0.60,
    CheckId.MISSING_PERMISSIONS_POLICY: 0.60,
    CheckId.NO_HTTPS_REDIRECT: 0.40,
    CheckId.INSECURE_COOKIE: 0.55,
    CheckId.DIRECTORY_LISTING_ENABLED: 0.20,
    CheckId.EXPOSED_SENSITIVE_FILE: 0.12,
    CheckId.WAF_ABSENT: 0.70,
    CheckId.LEGACY_TLS_VERSION: 0.50,
    CheckId.WEAK_TLS_CIPHER: 0.45,
    CheckId.EXPIRED_CERTIFICATE: 0.15,
    CheckId.SELF_SIGNED_CERTIFICATE: 0.15,
    CheckId.WEAK_CERTIFICATE_KEY: 0.12,
    CheckId.EXPOSED_INTERNAL_PORT: 0.30,
    CheckId.EXPOSED_MANAGEMENT_PORT: 0.35,
    CheckId.HIGH_RISK_PORT_OPEN: 0.35,
    CheckId.EXPOSED_DATABASE_PORT: 0.20,
    CheckId.OUTDATED_EXPOSED_SOFTWARE: 0.55,
    CheckId.EOL_SOFTWARE_EXPOSED: 0.45,
    CheckId.SPF_MISSING: 0.45,
    CheckId.DMARC_MISSING_OR_NONE: 0.65,
    CheckId.DKIM_MISSING: 0.55,
    CheckId.MTA_STS_MISSING: 0.70,
    CheckId.DNSSEC_MISSING: 0.80,
    CheckId.DNS_ZONE_TRANSFER_OPEN: 0.10,
    CheckId.NO_DDOS_PROTECTION: 0.75,
}

BASE_LOGIN_ADMIN = 0.75
BASE_LOGIN_OTHER = 0.10
BASE_DEV_ENV = 0.70

_HOST_JITTER = 0.15
_DEV_LABEL_B = "sandbox"


class SectorB:
    __slots__ = ("name", "prevalence", "neglect_a", "neglect_b", "min_subs", "max_subs")

    def __init__(
        self, name: str, prevalence: float, neglect_a: float, neglect_b: float, min_subs: int, max_subs: int
    ) -> None:
        self.name = name
        self.prevalence = prevalence
        self.neglect_a = neglect_a
        self.neglect_b = neglect_b
        self.min_subs = min_subs
        self.max_subs = max_subs


SECTORS_B: tuple[SectorB, ...] = (
    SectorB("saas", 0.30, 2.0, 2.5, 4, 10),
    SectorB("industrial", 0.25, 2.5, 2.0, 1, 4),
    SectorB("civic", 0.20, 2.0, 3.0, 2, 6),
    SectorB("commerce", 0.25, 2.2, 2.2, 3, 7),
)

_TLDS_B: tuple[str, ...] = ("com", "sa", "com.sa", "io", "net")
_TLD_WEIGHTS_B: dict[str, float] = {"com": 0.45, "sa": 0.20, "com.sa": 0.15, "io": 0.12, "net": 0.08}
_SECTOR_TAG: dict[str, str] = {"saas": "sw", "industrial": "in", "civic": "cv", "commerce": "cm"}


def _clamp01(value: float) -> float:
    return 0.0 if value < 0.0 else 1.0 if value > 1.0 else value


def _weighted_tld_b(rng: random.Random) -> str:
    r = rng.random() * sum(_TLD_WEIGHTS_B.values())
    upto = 0.0
    for tld in _TLDS_B:
        upto += _TLD_WEIGHTS_B[tld]
        if r <= upto:
            return tld
    return _TLDS_B[-1]


def _pick_sector_b(rng: random.Random) -> SectorB:
    r = rng.random() * sum(s.prevalence for s in SECTORS_B)
    upto = 0.0
    for s in SECTORS_B:
        upto += s.prevalence
        if r <= upto:
            return s
    return SECTORS_B[-1]


def _build_estate(rng: random.Random, sector: SectorB, index: int) -> tuple[str, list[str], str, str | None]:
    apex = f"biz{index:03d}-{_SECTOR_TAG[sector.name]}.{_weighted_tld_b(rng)}"
    m = rng.randint(sector.min_subs, sector.max_subs)
    subs = [f"svc{i + 1}" for i in range(m)]
    dev_label: str | None = None
    if m >= 3:
        subs[-1] = _DEV_LABEL_B
        dev_label = _DEV_LABEL_B
    hosts = [apex, *(f"{s}.{apex}" for s in subs)]
    admin_host = f"{subs[0]}.{apex}" if m >= 1 else apex
    dev_host = f"{dev_label}.{apex}" if dev_label is not None else None
    return apex, hosts, admin_host, dev_host


def _true_issues_b(
    rng: random.Random,
    hosts: list[str],
    apex: str,
    admin_host: str,
    dev_host: str | None,
    firm_neglect: float,
) -> tuple[list[InjectedFinding], bool]:
    true: list[InjectedFinding] = []
    for host in hosts:
        neglect = _clamp01(firm_neglect + rng.uniform(-_HOST_JITTER, _HOST_JITTER))
        for cat in _HOST_CATEGORIES:
            for check in CATEGORIES[cat]:
                if rng.random() < neglect * BASE_PREVALENCE[check]:
                    true.append(InjectedFinding(asset=host, check=check))
        base_login = BASE_LOGIN_ADMIN if host == admin_host else BASE_LOGIN_OTHER
        if rng.random() < neglect * base_login:
            true.append(InjectedFinding(asset=host, check=CheckId.EXPOSED_LOGIN_PANEL))
        if host == dev_host and rng.random() < neglect * BASE_DEV_ENV:
            true.append(InjectedFinding(asset=host, check=CheckId.EXPOSED_DEV_ENVIRONMENT))
        if host == apex:
            for cat in _APEX_CATEGORIES:
                for check in CATEGORIES[cat]:
                    if rng.random() < neglect * BASE_PREVALENCE[check]:
                        true.append(InjectedFinding(asset=apex, check=check))
    used_fallback = not true
    if used_fallback:
        true.append(InjectedFinding(asset=apex, check=CheckId.SPF_MISSING))
    return _dedup(true), used_fallback


def _firm_posture_label(neglect: float) -> str:
    if neglect < 0.34:
        return "strong"
    if neglect < 0.67:
        return "moderate"
    return "weak"


def _generate_case_b(
    index: int, seed: int, key: dict[CheckId, frozenset[str]], all_controls: frozenset[str]
) -> EvalCase:
    rng = random.Random(seed + index)
    sector = _pick_sector_b(rng)
    firm_neglect = rng.betavariate(sector.neglect_a, sector.neglect_b)
    apex, hosts, admin_host, dev_host = _build_estate(rng, sector, index)

    conditions, competence = _draw_conditions(rng, hosts)
    true, forced_true = _true_issues_b(rng, hosts, apex, admin_host, dev_host, firm_neglect)
    observed, forced_observe = _observe(rng, true, hosts, apex, conditions, competence)
    true_control_ids = _control_ids_for(true, key)
    attestations = _attestations(rng, f"evalb-{index:03d}", true_control_ids, all_controls)
    internal, off_surface = draw_off_surface_evidence(
        rng, f"evalb-{index:03d}", _firm_posture_label(firm_neglect)
    )
    attestations = attestations + off_surface

    per_asset: dict[str, frozenset[str]] = {}
    for inj in true:
        per_asset[inj.asset] = per_asset.get(inj.asset, frozenset()) | key[inj.check]

    sub_hosts = hosts[1:]
    assets = [SyntheticAsset(value=apex, asset_type=AssetType.DOMAIN.value)] + [
        SyntheticAsset(value=h, asset_type=AssetType.SUBDOMAIN.value) for h in sub_hosts
    ]
    profile = SyntheticProfile(profile_id=f"evalb-{index:03d}", apex=apex, assets=assets)
    baseline = 300.0 + 240.0 * len(observed)
    return EvalCase(
        case_id=f"evalb-{index:03d}",
        sector=sector.name,
        size_band="broad" if len(hosts) > 4 else "compact",
        profile=profile,
        injected=tuple(observed),
        true_injected=tuple(true),
        ground_truth=GroundTruth(
            control_ids=true_control_ids,
            observed_ids=_control_ids_for(observed, key),
            per_asset=per_asset,
        ),
        attestations=attestations,
        posture=_firm_posture_label(firm_neglect),
        baseline_seconds=baseline,
        internal_evidence=internal,
        forced_true_fallback=forced_true,
        forced_observe_fallback=forced_observe,
        scan_conditions=conditions,
        scanner_competence=competence,
    )


def generate_cases_b(n: int = 100, *, seed: int | None = None) -> list[EvalCase]:
    if n <= 0:
        raise ValueError("n must be positive")
    resolved = (get_settings().global_seed if seed is None else seed) + _SEED_OFFSET_B
    key = expert_key()
    all_controls = frozenset().union(*key.values())
    return [_generate_case_b(i, resolved, key, all_controls) for i in range(n)]
