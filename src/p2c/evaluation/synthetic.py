from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path

from p2c.config import get_settings
from p2c.discovery.synthetic import SyntheticAsset, SyntheticProfile
from p2c.mapping.catalog import load_default_index
from p2c.mapping.rules import RULES
from p2c.scanning.catalog import CheckId, build_finding
from p2c.schemas.enums import AssetType
from p2c.schemas.models import Attestation, Finding

EVAL_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
_ATTESTATION_VALID_UNTIL = EVAL_EPOCH + timedelta(days=365)

CATEGORIES: dict[str, tuple[CheckId, ...]] = {
    "web_headers": (
        CheckId.MISSING_HSTS,
        CheckId.MISSING_CSP,
        CheckId.MISSING_X_FRAME_OPTIONS,
        CheckId.MISSING_X_CONTENT_TYPE_OPTIONS,
        CheckId.MISSING_REFERRER_POLICY,
        CheckId.NO_HTTPS_REDIRECT,
        CheckId.MISSING_PERMISSIONS_POLICY,
        CheckId.INSECURE_COOKIE,
        CheckId.DIRECTORY_LISTING_ENABLED,
        CheckId.EXPOSED_SENSITIVE_FILE,
    ),
    "waf": (CheckId.WAF_ABSENT,),
    "tls": (
        CheckId.LEGACY_TLS_VERSION,
        CheckId.WEAK_TLS_CIPHER,
        CheckId.EXPIRED_CERTIFICATE,
        CheckId.SELF_SIGNED_CERTIFICATE,
        CheckId.WEAK_CERTIFICATE_KEY,
    ),
    "ports": (
        CheckId.EXPOSED_INTERNAL_PORT,
        CheckId.EXPOSED_MANAGEMENT_PORT,
        CheckId.HIGH_RISK_PORT_OPEN,
        CheckId.EXPOSED_DATABASE_PORT,
    ),
    "software": (CheckId.OUTDATED_EXPOSED_SOFTWARE,),
    "eol": (CheckId.EOL_SOFTWARE_EXPOSED,),
    "auth": (CheckId.EXPOSED_LOGIN_PANEL,),
    "dev_env": (CheckId.EXPOSED_DEV_ENVIRONMENT,),
    "email": (
        CheckId.SPF_MISSING,
        CheckId.DMARC_MISSING_OR_NONE,
        CheckId.DKIM_MISSING,
        CheckId.MTA_STS_MISSING,
    ),
    "dns": (CheckId.DNSSEC_MISSING, CheckId.DNS_ZONE_TRANSFER_OPEN),
    "ddos": (CheckId.NO_DDOS_PROTECTION,),
}
_CHECK_CATEGORY = {check: cat for cat, checks in CATEGORIES.items() for check in checks}

_HOST_CATEGORIES: tuple[str, ...] = ("web_headers", "waf", "tls", "ports", "software", "eol")
_APEX_CATEGORIES: tuple[str, ...] = ("email", "dns", "ddos")
_APEX_ONLY_CHECKS: frozenset[CheckId] = frozenset(c for cat in _APEX_CATEGORIES for c in CATEGORIES[cat])
_DEV_ONLY_CHECKS: frozenset[CheckId] = frozenset({CheckId.EXPOSED_DEV_ENVIRONMENT})

_DEV_LABELS: frozenset[str] = frozenset({"dev", "staging", "uat", "test", "sandbox"})
_ADMIN_LABELS: frozenset[str] = frozenset(
    {"admin", "portal", "vpn", "auth", "secure", "login", "eservices", "sis", "ib"}
)

_SUBSET_PROB: dict[CheckId, float] = {
    CheckId.MISSING_HSTS: 0.60,
    CheckId.MISSING_CSP: 0.55,
    CheckId.MISSING_X_FRAME_OPTIONS: 0.50,
    CheckId.MISSING_X_CONTENT_TYPE_OPTIONS: 0.45,
    CheckId.MISSING_REFERRER_POLICY: 0.45,
    CheckId.NO_HTTPS_REDIRECT: 0.30,
    CheckId.MISSING_PERMISSIONS_POLICY: 0.50,
    CheckId.INSECURE_COOKIE: 0.45,
    CheckId.DIRECTORY_LISTING_ENABLED: 0.20,
    CheckId.EXPOSED_SENSITIVE_FILE: 0.12,
    CheckId.WAF_ABSENT: 1.0,
    CheckId.LEGACY_TLS_VERSION: 0.50,
    CheckId.WEAK_TLS_CIPHER: 0.40,
    CheckId.EXPIRED_CERTIFICATE: 0.15,
    CheckId.SELF_SIGNED_CERTIFICATE: 0.18,
    CheckId.WEAK_CERTIFICATE_KEY: 0.15,
    CheckId.EXPOSED_INTERNAL_PORT: 0.30,
    CheckId.EXPOSED_MANAGEMENT_PORT: 0.50,
    CheckId.HIGH_RISK_PORT_OPEN: 0.50,
    CheckId.EXPOSED_DATABASE_PORT: 0.25,
    CheckId.OUTDATED_EXPOSED_SOFTWARE: 1.0,
    CheckId.EOL_SOFTWARE_EXPOSED: 1.0,
    CheckId.EXPOSED_LOGIN_PANEL: 1.0,
    CheckId.EXPOSED_DEV_ENVIRONMENT: 1.0,
    CheckId.SPF_MISSING: 0.50,
    CheckId.DMARC_MISSING_OR_NONE: 0.70,
    CheckId.DKIM_MISSING: 0.60,
    CheckId.MTA_STS_MISSING: 0.70,
    CheckId.DNSSEC_MISSING: 0.85,
    CheckId.DNS_ZONE_TRANSFER_OPEN: 0.10,
    CheckId.NO_DDOS_PROTECTION: 1.0,
}

SENSITIVITY: dict[CheckId, float] = {
    CheckId.MISSING_HSTS: 0.99,
    CheckId.MISSING_CSP: 0.99,
    CheckId.MISSING_X_FRAME_OPTIONS: 0.99,
    CheckId.MISSING_X_CONTENT_TYPE_OPTIONS: 0.99,
    CheckId.MISSING_REFERRER_POLICY: 0.99,
    CheckId.NO_HTTPS_REDIRECT: 0.98,
    CheckId.MISSING_PERMISSIONS_POLICY: 0.99,
    CheckId.INSECURE_COOKIE: 0.98,
    CheckId.DIRECTORY_LISTING_ENABLED: 0.92,
    CheckId.EXPOSED_SENSITIVE_FILE: 0.75,
    CheckId.WAF_ABSENT: 0.90,
    CheckId.LEGACY_TLS_VERSION: 0.96,
    CheckId.WEAK_TLS_CIPHER: 0.96,
    CheckId.EXPIRED_CERTIFICATE: 0.99,
    CheckId.SELF_SIGNED_CERTIFICATE: 0.98,
    CheckId.WEAK_CERTIFICATE_KEY: 0.97,
    CheckId.EXPOSED_INTERNAL_PORT: 0.95,
    CheckId.EXPOSED_MANAGEMENT_PORT: 0.95,
    CheckId.HIGH_RISK_PORT_OPEN: 0.95,
    CheckId.EXPOSED_DATABASE_PORT: 0.95,
    CheckId.OUTDATED_EXPOSED_SOFTWARE: 0.72,
    CheckId.EOL_SOFTWARE_EXPOSED: 0.70,
    CheckId.EXPOSED_LOGIN_PANEL: 0.88,
    CheckId.EXPOSED_DEV_ENVIRONMENT: 0.96,
    CheckId.SPF_MISSING: 0.99,
    CheckId.DMARC_MISSING_OR_NONE: 0.99,
    CheckId.DKIM_MISSING: 0.93,
    CheckId.MTA_STS_MISSING: 0.98,
    CheckId.DNSSEC_MISSING: 0.99,
    CheckId.DNS_ZONE_TRANSFER_OPEN: 0.90,
    CheckId.NO_DDOS_PROTECTION: 0.85,
}
FALSE_ALARM: dict[CheckId, float] = {
    CheckId.MISSING_HSTS: 0.0,
    CheckId.MISSING_CSP: 0.0,
    CheckId.MISSING_X_FRAME_OPTIONS: 0.0,
    CheckId.MISSING_X_CONTENT_TYPE_OPTIONS: 0.0,
    CheckId.MISSING_REFERRER_POLICY: 0.0,
    CheckId.NO_HTTPS_REDIRECT: 0.0,
    CheckId.MISSING_PERMISSIONS_POLICY: 0.0,
    CheckId.INSECURE_COOKIE: 0.0,
    CheckId.DIRECTORY_LISTING_ENABLED: 0.03,
    CheckId.EXPOSED_SENSITIVE_FILE: 0.06,
    CheckId.WAF_ABSENT: 0.20,
    CheckId.LEGACY_TLS_VERSION: 0.02,
    CheckId.WEAK_TLS_CIPHER: 0.02,
    CheckId.EXPIRED_CERTIFICATE: 0.0,
    CheckId.SELF_SIGNED_CERTIFICATE: 0.0,
    CheckId.WEAK_CERTIFICATE_KEY: 0.0,
    CheckId.EXPOSED_INTERNAL_PORT: 0.04,
    CheckId.EXPOSED_MANAGEMENT_PORT: 0.04,
    CheckId.HIGH_RISK_PORT_OPEN: 0.04,
    CheckId.EXPOSED_DATABASE_PORT: 0.04,
    CheckId.OUTDATED_EXPOSED_SOFTWARE: 0.06,
    CheckId.EOL_SOFTWARE_EXPOSED: 0.08,
    CheckId.EXPOSED_LOGIN_PANEL: 0.08,
    CheckId.EXPOSED_DEV_ENVIRONMENT: 0.04,
    CheckId.SPF_MISSING: 0.0,
    CheckId.DMARC_MISSING_OR_NONE: 0.0,
    CheckId.DKIM_MISSING: 0.24,
    CheckId.MTA_STS_MISSING: 0.0,
    CheckId.DNSSEC_MISSING: 0.0,
    CheckId.DNS_ZONE_TRANSFER_OPEN: 0.02,
    CheckId.NO_DDOS_PROTECTION: 0.20,
}
LOW_CONFIDENCE_FA = 0.08
LOW_CONFIDENCE_CHECKS: frozenset[CheckId] = frozenset(
    c for c, v in FALSE_ALARM.items() if v >= LOW_CONFIDENCE_FA
)


SCAN_CONDITIONS: tuple[str, ...] = ("reachable", "throttled", "cdn_fronted", "blocked")
CONDITION_FACTOR_ORIGIN: dict[str, float] = {
    "reachable": 1.00,
    "throttled": 0.90,
    "cdn_fronted": 0.40,
    "blocked": 0.20,
}
CONDITION_FACTOR_EDGE: dict[str, float] = {
    "reachable": 1.00,
    "throttled": 0.92,
    "cdn_fronted": 0.95,
    "blocked": 0.20,
}
CONDITION_SHARES: dict[str, float] = {
    "reachable": 0.85,
    "throttled": 0.09,
    "cdn_fronted": 0.05,
    "blocked": 0.01,
}
COMPETENCE_MIN, COMPETENCE_MAX = 0.97, 1.00
_ORIGIN_CHECKS: frozenset[CheckId] = frozenset(
    c for cat in ("ports", "software", "eol", "dev_env") for c in CATEGORIES[cat]
) | {CheckId.EXPOSED_SENSITIVE_FILE, CheckId.DIRECTORY_LISTING_ENABLED}
_HOST_FETCHED_CHECKS: frozenset[CheckId] = frozenset(c for c in SENSITIVITY if c not in _APEX_ONLY_CHECKS)
_FALSE_ALARM_CHECKS: tuple[CheckId, ...] = (
    CheckId.WAF_ABSENT,
    CheckId.LEGACY_TLS_VERSION,
    CheckId.WEAK_TLS_CIPHER,
    CheckId.EXPOSED_INTERNAL_PORT,
    CheckId.EXPOSED_MANAGEMENT_PORT,
    CheckId.HIGH_RISK_PORT_OPEN,
    CheckId.EXPOSED_DATABASE_PORT,
    CheckId.OUTDATED_EXPOSED_SOFTWARE,
    CheckId.EOL_SOFTWARE_EXPOSED,
    CheckId.EXPOSED_SENSITIVE_FILE,
    CheckId.DIRECTORY_LISTING_ENABLED,
    CheckId.DKIM_MISSING,
    CheckId.NO_DDOS_PROTECTION,
    CheckId.EXPOSED_LOGIN_PANEL,
    CheckId.EXPOSED_DEV_ENVIRONMENT,
    CheckId.DNS_ZONE_TRANSFER_OPEN,
)


@dataclass(frozen=True)
class Sector:
    name: str
    prevalence: float
    weights: dict[str, float]


WEIGHT_KEYS: tuple[str, ...] = (
    "web_headers",
    "waf",
    "tls",
    "ports",
    "software",
    "eol",
    "auth",
    "ddos",
    "email",
    "dns",
    "dev_env",
)


def _w(*values: float) -> dict[str, float]:
    return dict(zip(WEIGHT_KEYS, values, strict=True))


SECTORS: tuple[Sector, ...] = (
    Sector("retail_wholesale", 0.27, _w(0.72, 0.72, 0.55, 0.50, 0.56, 0.48, 0.54, 0.62, 0.60, 0.78, 0.45)),
    Sector("construction", 0.20, _w(0.42, 0.50, 0.40, 0.55, 0.62, 0.62, 0.50, 0.40, 0.65, 0.82, 0.40)),
    Sector("food_accommodation", 0.10, _w(0.70, 0.70, 0.55, 0.48, 0.58, 0.52, 0.50, 0.60, 0.62, 0.80, 0.42)),
    Sector("prof_admin_services", 0.14, _w(0.55, 0.58, 0.45, 0.50, 0.55, 0.50, 0.56, 0.48, 0.60, 0.78, 0.48)),
    Sector("manufacturing", 0.10, _w(0.42, 0.50, 0.42, 0.60, 0.65, 0.65, 0.50, 0.40, 0.63, 0.82, 0.42)),
    Sector("transport_logistics", 0.05, _w(0.45, 0.52, 0.45, 0.60, 0.58, 0.56, 0.54, 0.45, 0.62, 0.80, 0.45)),
    Sector("education", 0.07, _w(0.58, 0.62, 0.45, 0.55, 0.64, 0.60, 0.72, 0.50, 0.62, 0.80, 0.62)),
    Sector("health", 0.07, _w(0.58, 0.65, 0.48, 0.55, 0.62, 0.56, 0.75, 0.52, 0.60, 0.80, 0.60)),
)


@dataclass(frozen=True)
class SizeBand:
    name: str
    share: float
    min_subs: int
    max_subs: int
    posture_shares: dict[str, float]


SIZE_BANDS: tuple[SizeBand, ...] = (
    SizeBand("small", 0.89, 1, 4, {"strong": 0.15, "moderate": 0.35, "weak": 0.50}),
    SizeBand("medium", 0.11, 3, 8, {"strong": 0.30, "moderate": 0.40, "weak": 0.30}),
)

POSTURE_MULT: dict[str, float] = {"strong": 0.20, "moderate": 0.55, "weak": 1.00}
_POSTURE_NAMES: tuple[str, ...] = ("strong", "moderate", "weak")


@dataclass(frozen=True)
class Posture:
    name: str
    share: float
    mult: float


def _marginal_posture_shares() -> dict[str, float]:
    out = dict.fromkeys(_POSTURE_NAMES, 0.0)
    for band in SIZE_BANDS:
        for name in _POSTURE_NAMES:
            out[name] += band.share * band.posture_shares[name]
    return out


_MARGINAL_POSTURE = _marginal_posture_shares()
POSTURES: tuple[Posture, ...] = tuple(
    Posture(name, round(_MARGINAL_POSTURE[name], 4), POSTURE_MULT[name]) for name in _POSTURE_NAMES
)
_POSTURE_BY_NAME: dict[str, Posture] = {p.name: p for p in POSTURES}

P_ATTEST_CLEAN = 0.70
P_OVERSTATE = 0.50

_TLDS: tuple[str, ...] = ("com", "com.sa", "sa", "net.sa")
_TLD_WEIGHTS: dict[str, float] = {"com": 0.55, "com.sa": 0.20, "sa": 0.15, "net.sa": 0.10}

_SUBDOMAIN_POOLS: dict[str, tuple[str, ...]] = {
    "retail_wholesale": ("www", "shop", "checkout", "api", "cdn", "mail", "pay", "einvoice", "admin", "staging", "dev"),
    "construction": ("www", "mail", "portal", "projects", "vpn", "api", "docs", "dev", "staging", "test"),
    "food_accommodation": ("www", "book", "order", "menu", "api", "mail", "cdn", "einvoice", "admin", "staging", "dev"),
    "prof_admin_services": ("www", "portal", "mail", "api", "crm", "vpn", "docs", "einvoice", "login", "staging", "dev"),
    "manufacturing": ("www", "mail", "portal", "erp", "api", "vpn", "shop", "secure", "dev", "uat"),
    "transport_logistics": ("www", "track", "api", "portal", "mail", "vpn", "edi", "fleet", "dev", "test"),
    "education": ("www", "portal", "lms", "sis", "mail", "vpn", "library", "elearning", "dev", "staging"),
    "health": ("www", "portal", "patients", "appointments", "api", "mail", "vpn", "lab", "dev", "uat"),
}
MIN_SUBS = min(b.min_subs for b in SIZE_BANDS)
MAX_SUBS = max(b.max_subs for b in SIZE_BANDS)


def expert_key() -> dict[CheckId, frozenset[str]]:
    index = load_default_index()
    key: dict[CheckId, frozenset[str]] = {}
    for check, rule in RULES.items():
        ids = frozenset(rule.control_ids)
        missing = [cid for cid in ids if index.get(cid) is None]
        if missing:
            raise ValueError(f"expert key for {check.value} references non-catalog ids {missing}")
        key[check] = ids
    return key


@dataclass(frozen=True)
class InjectedFinding:

    asset: str
    check: CheckId


@dataclass(frozen=True)
class InternalAssessment:
    control_id: str
    compliant: bool


@dataclass(frozen=True)
class GroundTruth:
    control_ids: frozenset[str]
    observed_ids: frozenset[str]
    per_asset: dict[str, frozenset[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class EvalCase:

    case_id: str
    sector: str
    size_band: str
    profile: SyntheticProfile
    injected: tuple[InjectedFinding, ...]
    true_injected: tuple[InjectedFinding, ...]
    ground_truth: GroundTruth
    attestations: tuple[Attestation, ...]
    posture: str
    baseline_seconds: float
    internal_evidence: tuple[InternalAssessment, ...] = ()
    forced_true_fallback: bool = False
    forced_observe_fallback: bool = False
    scan_conditions: dict[str, str] = field(default_factory=dict)
    scanner_competence: float = 1.0

    def pipeline_input(self) -> SyntheticProfile:
        return self.profile

    def findings(self, *, now: datetime = EVAL_EPOCH, consent_ref: str = "eval") -> list[Finding]:
        return [
            build_finding(
                inj.check,
                asset=inj.asset,
                observed_state=f"{inj.check.value} detected on {inj.asset} (synthetic)",
                consent_ref=consent_ref,
                source_tool="atlas-scan:synthetic",
                tool_version="synthetic-1",
                finding_id=f"{inj.check.value}:{self.case_id}:{inj.asset}",
                now=now,
            ).model_copy(update={"control_ids": []})
            for inj in self.injected
        ]


def _weighted_tld(rng: random.Random) -> str:
    r = rng.random() * sum(_TLD_WEIGHTS.values())
    upto = 0.0
    for tld in _TLDS:
        upto += _TLD_WEIGHTS[tld]
        if r <= upto:
            return tld
    return _TLDS[-1]


IDN_APEX_SHARE = 0.01
_IDN_APEX_WORDS: tuple[str, ...] = ("منشاة", "مؤسسة", "شركة")
_ARABIC_DIGITS = "٠١٢٣٤٥٦٧٨٩"


def _idn_apex_label(rng: random.Random, index: int) -> str:
    word = rng.choice(_IDN_APEX_WORDS)
    digits = "".join(_ARABIC_DIGITS[int(c)] for c in f"{index:03d}")
    return f"{word}{digits}م".encode("idna").decode("ascii")


def _domain_for(rng: random.Random, index: int) -> str:
    suffix = rng.choice(("grp", "co", "ltd", "org"))
    tld = _weighted_tld(rng)
    idn_rng = random.Random(0xA11A + index)
    if tld != "com" and idn_rng.random() < IDN_APEX_SHARE:
        return f"{_idn_apex_label(idn_rng, index)}.{tld}"
    return f"sme{index:03d}-{suffix}.{tld}"


def _host_label(host: str, apex: str) -> str:
    return "apex" if host == apex else host.split(".", 1)[0]


def _draw_subset(rng: random.Random, category: str) -> list[CheckId]:
    checks = CATEGORIES[category]
    chosen = [c for c in checks if rng.random() < _SUBSET_PROB[c]]
    if not chosen:
        chosen = [rng.choice(checks)]
    return chosen


def _control_ids_for(injected: list[InjectedFinding], key: dict[CheckId, frozenset[str]]) -> frozenset[str]:
    if not injected:
        return frozenset()
    return frozenset().union(*(key[i.check] for i in injected))


def _dedup(injected: list[InjectedFinding]) -> list[InjectedFinding]:
    seen: set[tuple[str, CheckId]] = set()
    out: list[InjectedFinding] = []
    for inj in injected:
        marker = (inj.asset, inj.check)
        if marker not in seen:
            seen.add(marker)
            out.append(inj)
    return out


def _true_issues(
    rng: random.Random, sector: Sector, hosts: list[str], apex: str, mult: float
) -> tuple[list[InjectedFinding], bool]:
    true: list[InjectedFinding] = []
    for host in hosts:
        label = _host_label(host, apex)
        for cat in _HOST_CATEGORIES:
            if rng.random() < sector.weights[cat] * mult:
                true.extend(InjectedFinding(asset=host, check=c) for c in _draw_subset(rng, cat))
        w_auth = sector.weights["auth"]
        p_auth = (min(1.0, w_auth * 2.0) if label in _ADMIN_LABELS else w_auth * 0.35) * mult
        if rng.random() < p_auth:
            true.append(InjectedFinding(asset=host, check=CheckId.EXPOSED_LOGIN_PANEL))
        if label in _DEV_LABELS and rng.random() < sector.weights["dev_env"] * mult:
            true.append(InjectedFinding(asset=host, check=CheckId.EXPOSED_DEV_ENVIRONMENT))
    for cat in _APEX_CATEGORIES:
        if rng.random() < sector.weights[cat] * mult:
            true.extend(InjectedFinding(asset=apex, check=c) for c in _draw_subset(rng, cat))
    used_fallback = not true
    if used_fallback:
        true.append(InjectedFinding(asset=apex, check=CheckId.SPF_MISSING))
    return _dedup(true), used_fallback


P_ATTEST_EXPIRED = 0.10
P_ATTEST_NOT_YET = 0.05


def _attestation_window(rng: random.Random) -> tuple[datetime, datetime]:
    r = rng.random()
    if r < P_ATTEST_EXPIRED:
        return EVAL_EPOCH - timedelta(days=400), EVAL_EPOCH - timedelta(days=1 + int(59 * rng.random()))
    if r < P_ATTEST_EXPIRED + P_ATTEST_NOT_YET:
        return EVAL_EPOCH + timedelta(days=1 + int(29 * rng.random())), EVAL_EPOCH + timedelta(days=365)
    return EVAL_EPOCH - timedelta(days=30), EVAL_EPOCH + timedelta(days=30 + int(335 * rng.random()))


def _attestations(
    rng: random.Random, case_id: str, true_control_ids: frozenset[str], all_controls: frozenset[str]
) -> tuple[Attestation, ...]:
    out: list[Attestation] = []
    for cid in sorted(all_controls):
        violated = cid in true_control_ids
        if rng.random() < (P_OVERSTATE if violated else P_ATTEST_CLEAN):
            digest = hashlib.sha256(f"{case_id}:{cid}".encode()).hexdigest()
            valid_from, valid_until = _attestation_window(rng)
            out.append(
                Attestation(
                    attestation_id=f"att-{case_id}-{cid}",
                    control_id=cid,
                    statement=f"Control {cid} is implemented and operating effectively.",
                    signer_identity=f"ciso@{case_id}",
                    payload_hash=digest,
                    valid_from=valid_from,
                    valid_until=valid_until,
                )
            )
    return tuple(out)


_OVERLAY_PATH = Path(__file__).resolve().parents[3] / "taxonomy" / "release" / "sort_overlay.json"

OFF_SURFACE_COVERAGE: dict[str, float] = {"strong": 0.20, "moderate": 0.12, "weak": 0.05}
P_INTERNAL_GAP = 0.25


@lru_cache(maxsize=1)
def off_surface_pools() -> tuple[tuple[str, ...], tuple[str, ...]]:
    from p2c.scoring.assemble import TIER1_CHECKABLE
    from p2c.scoring.contradictions import control_related

    rows = json.loads(_OVERLAY_PATH.read_text(encoding="utf-8"))["controls"]
    pools: dict[int, list[str]] = {2: [], 3: []}
    for row in rows:
        tier = int(row["tier"])
        if tier in pools:
            pools[tier].append(str(row["id"]))
    for tier, ids in pools.items():
        reachable = [c for c in ids if any(control_related(c, t) for t in TIER1_CHECKABLE)]
        if reachable:
            raise ValueError(f"off-surface tier-{tier} pool holds scan-reachable controls {reachable}")
    return tuple(sorted(pools[2])), tuple(sorted(pools[3]))


def _off_surface_internal(rng: random.Random, posture: str) -> tuple[InternalAssessment, ...]:
    internal, _ = off_surface_pools()
    coverage = OFF_SURFACE_COVERAGE[posture]
    return tuple(
        InternalAssessment(control_id=cid, compliant=rng.random() >= P_INTERNAL_GAP)
        for cid in internal
        if rng.random() < coverage
    )


def _off_surface_declarations(
    rng: random.Random, case_id: str, posture: str
) -> tuple[Attestation, ...]:
    _, declarable = off_surface_pools()
    coverage = OFF_SURFACE_COVERAGE[posture]
    out: list[Attestation] = []
    for cid in declarable:
        if rng.random() >= coverage:
            continue
        digest = hashlib.sha256(f"{case_id}:{cid}".encode()).hexdigest()
        valid_from, valid_until = _attestation_window(rng)
        out.append(
            Attestation(
                attestation_id=f"att-{case_id}-{cid}",
                control_id=cid,
                statement=f"Control {cid} is implemented and operating effectively.",
                signer_identity=f"ciso@{case_id}",
                payload_hash=digest,
                valid_from=valid_from,
                valid_until=valid_until,
            )
        )
    return tuple(out)


def draw_off_surface_evidence(
    rng: random.Random, case_id: str, posture: str
) -> tuple[tuple[InternalAssessment, ...], tuple[Attestation, ...]]:
    return _off_surface_internal(rng, posture), _off_surface_declarations(rng, case_id, posture)


def _weighted_condition(rng: random.Random) -> str:
    r = rng.random()
    upto = 0.0
    for cond in SCAN_CONDITIONS:
        upto += CONDITION_SHARES[cond]
        if r <= upto:
            return cond
    return SCAN_CONDITIONS[-1]


def _draw_conditions(rng: random.Random, hosts: list[str]) -> tuple[dict[str, str], float]:
    competence = COMPETENCE_MIN + (COMPETENCE_MAX - COMPETENCE_MIN) * rng.random()
    conditions = {host: _weighted_condition(rng) for host in hosts}
    return conditions, competence


def _condition_factor(check: CheckId, condition: str) -> float:
    table = CONDITION_FACTOR_ORIGIN if check in _ORIGIN_CHECKS else CONDITION_FACTOR_EDGE
    return table[condition]


def _effective_sensitivity(check: CheckId, host: str, conditions: dict[str, str], competence: float) -> float:
    base = SENSITIVITY[check]
    if check in _HOST_FETCHED_CHECKS:
        return base * competence * _condition_factor(check, conditions[host])
    return base


def _observe(
    rng: random.Random,
    true: list[InjectedFinding],
    hosts: list[str],
    apex: str,
    conditions: dict[str, str],
    competence: float,
) -> tuple[list[InjectedFinding], bool]:
    true_present = {(i.asset, i.check) for i in true}
    observed: list[InjectedFinding] = []
    for inj in true:
        if rng.random() < _effective_sensitivity(inj.check, inj.asset, conditions, competence):
            observed.append(inj)
    for host in hosts:
        label = _host_label(host, apex)
        for check in _FALSE_ALARM_CHECKS:
            if check in _APEX_ONLY_CHECKS and host != apex:
                continue
            if check in _DEV_ONLY_CHECKS and label not in _DEV_LABELS:
                continue
            if (host, check) in true_present:
                continue
            fa = FALSE_ALARM[check]
            if check in _HOST_FETCHED_CHECKS:
                fa *= _condition_factor(check, conditions[host])
            if rng.random() < fa:
                observed.append(InjectedFinding(asset=host, check=check))
    used_fallback = bool(true) and not observed
    if used_fallback:
        observed.append(true[0])
    return _dedup(observed), used_fallback


def _generate_case(
    index: int,
    seed: int,
    key: dict[CheckId, frozenset[str]],
    all_controls: frozenset[str],
    *,
    clean: bool = False,
) -> EvalCase:
    rng = random.Random(seed + index)
    band = _pick_size_band(rng)
    sector = _weighted_choice(rng, SECTORS, [s.prevalence for s in SECTORS])
    posture = _pick_posture(rng, band)
    apex = _domain_for(rng, index)

    pool = _SUBDOMAIN_POOLS[sector.name]
    n_subs = min(rng.randint(band.min_subs, band.max_subs), len(pool))
    sub_names = rng.sample(pool, n_subs)
    hosts = [apex, *(f"{s}.{apex}" for s in sub_names)]

    conditions, competence = _draw_conditions(rng, hosts)
    true: list[InjectedFinding] = []
    forced_true = False
    if not clean:
        true, forced_true = _true_issues(rng, sector, hosts, apex, posture.mult)
    observed, forced_observe = _observe(rng, true, hosts, apex, conditions, competence)
    true_control_ids = _control_ids_for(true, key)
    attestations = _attestations(rng, f"eval-{index:03d}", true_control_ids, all_controls)
    internal, off_surface = draw_off_surface_evidence(rng, f"eval-{index:03d}", posture.name)
    attestations = attestations + off_surface

    per_asset: dict[str, frozenset[str]] = {}
    for inj in true:
        per_asset[inj.asset] = per_asset.get(inj.asset, frozenset()) | key[inj.check]

    assets = [SyntheticAsset(value=apex, asset_type=AssetType.DOMAIN.value)] + [
        SyntheticAsset(value=f"{s}.{apex}", asset_type=AssetType.SUBDOMAIN.value) for s in sub_names
    ]
    profile = SyntheticProfile(profile_id=f"eval-{index:03d}", apex=apex, assets=assets)
    baseline = 300.0 + 240.0 * len(observed)
    return EvalCase(
        case_id=f"eval-{index:03d}",
        sector=sector.name,
        size_band=band.name,
        profile=profile,
        injected=tuple(observed),
        true_injected=tuple(true),
        ground_truth=GroundTruth(
            control_ids=true_control_ids,
            observed_ids=_control_ids_for(observed, key),
            per_asset=per_asset,
        ),
        attestations=attestations,
        posture=posture.name,
        baseline_seconds=baseline,
        internal_evidence=internal,
        forced_true_fallback=forced_true,
        forced_observe_fallback=forced_observe,
        scan_conditions=conditions,
        scanner_competence=competence,
    )


def _weighted_choice(rng: random.Random, items: tuple[Sector, ...], weights: list[float]) -> Sector:
    total = sum(weights)
    r = rng.random() * total
    upto = 0.0
    for item, w in zip(items, weights, strict=True):
        upto += w
        if r <= upto:
            return item
    return items[-1]


def _pick_size_band(rng: random.Random) -> SizeBand:
    r = rng.random() * sum(b.share for b in SIZE_BANDS)
    upto = 0.0
    for b in SIZE_BANDS:
        upto += b.share
        if r <= upto:
            return b
    return SIZE_BANDS[-1]


def _pick_posture(rng: random.Random, band: SizeBand) -> Posture:
    shares = band.posture_shares
    r = rng.random() * sum(shares.values())
    upto = 0.0
    for name in _POSTURE_NAMES:
        upto += shares[name]
        if r <= upto:
            return _POSTURE_BY_NAME[name]
    return _POSTURE_BY_NAME[_POSTURE_NAMES[-1]]


def generate_cases(n: int = 100, *, seed: int | None = None) -> list[EvalCase]:
    if n <= 0:
        raise ValueError("n must be positive")
    resolved = get_settings().global_seed if seed is None else seed
    key = expert_key()
    all_controls = frozenset().union(*key.values())
    return [_generate_case(i, resolved, key, all_controls) for i in range(n)]


def generate_clean_cases(n: int = 30, *, seed: int | None = None) -> list[EvalCase]:
    if n <= 0:
        raise ValueError("n must be positive")
    resolved = (get_settings().global_seed if seed is None else seed) + 500_000
    key = expert_key()
    all_controls = frozenset().union(*key.values())
    return [_generate_case(i, resolved, key, all_controls, clean=True) for i in range(n)]
