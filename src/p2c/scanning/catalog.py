from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import Finding, severity_from_cvss

_CONTROL_ID_RE = re.compile(r"^\d{1,2}-\d{1,2}(-\d{1,2}){0,2}$")


def is_valid_control_id(control_id: str) -> bool:
    return bool(_CONTROL_ID_RE.match(control_id))


class CheckId(StrEnum):

    MISSING_HSTS = "missing_hsts"
    MISSING_CSP = "missing_csp"
    MISSING_X_FRAME_OPTIONS = "missing_x_frame_options"
    MISSING_X_CONTENT_TYPE_OPTIONS = "missing_x_content_type_options"
    MISSING_REFERRER_POLICY = "missing_referrer_policy"
    NO_HTTPS_REDIRECT = "no_https_redirect"
    LEGACY_TLS_VERSION = "legacy_tls_version"
    WEAK_TLS_CIPHER = "weak_tls_cipher"
    EXPIRED_CERTIFICATE = "expired_certificate"
    WAF_ABSENT = "waf_absent"
    EXPOSED_INTERNAL_PORT = "exposed_internal_port"
    EXPOSED_MANAGEMENT_PORT = "exposed_management_port"
    HIGH_RISK_PORT_OPEN = "high_risk_port_open"
    OUTDATED_EXPOSED_SOFTWARE = "outdated_exposed_software"
    SPF_MISSING = "spf_missing"
    DMARC_MISSING_OR_NONE = "dmarc_missing_or_none"
    DKIM_MISSING = "dkim_missing"
    MTA_STS_MISSING = "mta_sts_missing"
    SELF_SIGNED_CERTIFICATE = "self_signed_certificate"
    WEAK_CERTIFICATE_KEY = "weak_certificate_key"
    INSECURE_COOKIE = "insecure_cookie"
    DIRECTORY_LISTING_ENABLED = "directory_listing_enabled"
    EXPOSED_SENSITIVE_FILE = "exposed_sensitive_file"
    MISSING_PERMISSIONS_POLICY = "missing_permissions_policy"
    EXPOSED_DEV_ENVIRONMENT = "exposed_dev_environment"
    DNSSEC_MISSING = "dnssec_missing"
    DNS_ZONE_TRANSFER_OPEN = "dns_zone_transfer_open"
    NO_DDOS_PROTECTION = "no_ddos_protection"
    EXPOSED_LOGIN_PANEL = "exposed_login_panel"
    EXPOSED_DATABASE_PORT = "exposed_database_port"
    EOL_SOFTWARE_EXPOSED = "eol_software_exposed"


@dataclass(frozen=True)
class CheckSpec:

    check_id: CheckId
    title: str
    control_ids: tuple[str, ...]
    evidence_tier: EvidenceTier
    cvss_vector: str
    cvss_score: float
    remediation: str

    @property
    def severity(self) -> str:
        return severity_from_cvss(self.cvss_score).value


def _spec(
    check_id: CheckId,
    title: str,
    control_ids: tuple[str, ...],
    score: float,
    vector: str,
    remediation: str,
) -> CheckSpec:
    return CheckSpec(check_id, title, control_ids, EvidenceTier.TIER_1, vector, score, remediation)


_HDR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
_HDR_MED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
_TLS_HIGH = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
_PORT_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
_PORT_MED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

CATALOG: dict[CheckId, CheckSpec] = {
    c.check_id: c
    for c in [
        _spec(
            CheckId.MISSING_HSTS,
            "HSTS header absent",
            ("2-15-3-3", "2-8-3-3"),
            5.4,
            _HDR_MED,
            "Set Strict-Transport-Security with max-age>=15768000 and includeSubDomains.",
        ),
        _spec(
            CheckId.MISSING_CSP,
            "Content-Security-Policy absent",
            ("2-15-3-3",),
            5.4,
            _HDR_MED,
            "Define a restrictive Content-Security-Policy.",
        ),
        _spec(
            CheckId.MISSING_X_FRAME_OPTIONS,
            "X-Frame-Options absent (clickjacking)",
            ("2-15-3-3",),
            5.4,
            _HDR_MED,
            "Set X-Frame-Options: DENY (or CSP frame-ancestors 'none').",
        ),
        _spec(
            CheckId.MISSING_X_CONTENT_TYPE_OPTIONS,
            "X-Content-Type-Options absent",
            ("2-15-3-3",),
            3.1,
            _HDR,
            "Set X-Content-Type-Options: nosniff.",
        ),
        _spec(
            CheckId.MISSING_REFERRER_POLICY,
            "Referrer-Policy absent",
            ("2-15-3-3",),
            3.1,
            _HDR,
            "Set Referrer-Policy: strict-origin-when-cross-origin.",
        ),
        _spec(
            CheckId.NO_HTTPS_REDIRECT,
            "HTTP served without HTTPS redirect",
            ("2-15-3-3",),
            6.5,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "Enforce HTTPS; redirect all HTTP to HTTPS.",
        ),
        _spec(
            CheckId.LEGACY_TLS_VERSION,
            "Legacy TLS version (1.0/1.1) enabled",
            ("2-8-3-3",),
            7.4,
            _TLS_HIGH,
            "Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3).",
        ),
        _spec(
            CheckId.WEAK_TLS_CIPHER,
            "Weak TLS cipher negotiated",
            ("2-8-3-3",),
            7.4,
            _TLS_HIGH,
            "Remove weak/export/NULL cipher suites; use modern AEAD ciphers.",
        ),
        _spec(
            CheckId.EXPIRED_CERTIFICATE,
            "Expired or not-yet-valid certificate",
            ("2-8-3-3",),
            7.4,
            _TLS_HIGH,
            "Renew the certificate; automate renewal.",
        ),
        _spec(
            CheckId.WAF_ABSENT,
            "No WAF fingerprint on external web app",
            ("2-15-3-1",),
            5.3,
            _PORT_MED,
            "Deploy a WAF in blocking mode with OWASP rule sets.",
        ),
        _spec(
            CheckId.EXPOSED_INTERNAL_PORT,
            "Internal service port exposed to internet",
            ("2-5-3-1",),
            7.5,
            _PORT_HIGH,
            "Move internal services behind a firewall; restrict internet exposure.",
        ),
        _spec(
            CheckId.EXPOSED_MANAGEMENT_PORT,
            "Management service (SSH/RDP) directly exposed",
            ("2-2-3-2", "2-2-3-1"),
            5.3,
            _PORT_MED,
            "Restrict SSH/RDP behind VPN+MFA; close direct exposure.",
        ),
        _spec(
            CheckId.HIGH_RISK_PORT_OPEN,
            "Unnecessary/high-risk port open",
            ("2-5-3-5",),
            5.3,
            _PORT_MED,
            "Close unnecessary ports; document approved exceptions.",
        ),
        _spec(
            CheckId.OUTDATED_EXPOSED_SOFTWARE,
            "Outdated exposed software version",
            ("2-10-3-4", "2-10-3-1"),
            7.5,
            _PORT_HIGH,
            "Patch internet-facing software; establish a patch SLA.",
        ),
        _spec(
            CheckId.SPF_MISSING,
            "SPF record missing/misconfigured",
            ("2-4-3-5",),
            5.4,
            _HDR_MED,
            "Publish an SPF record covering all sending IPs.",
        ),
        _spec(
            CheckId.DMARC_MISSING_OR_NONE,
            "DMARC absent or policy=none",
            ("2-4-3-5",),
            5.4,
            _HDR_MED,
            "Publish DMARC at quarantine or reject.",
        ),
        _spec(
            CheckId.DKIM_MISSING,
            "DKIM not found for probed selectors (selector-limited)",
            ("2-4-3-5",),
            3.1,
            _HDR,
            "Configure DKIM signing; provide known selectors at onboarding.",
        ),
        _spec(
            CheckId.MTA_STS_MISSING,
            "MTA-STS policy absent (no enforced inbound TLS)",
            ("2-4-3-5",),
            3.1,
            _HDR,
            "Publish an MTA-STS policy and TLS-RPT record to enforce inbound SMTP TLS.",
        ),
        _spec(
            CheckId.SELF_SIGNED_CERTIFICATE,
            "Self-signed or untrusted certificate chain",
            ("2-8-3-3",),
            7.4,
            _TLS_HIGH,
            "Replace with a certificate from a trusted CA; automate issuance and renewal.",
        ),
        _spec(
            CheckId.WEAK_CERTIFICATE_KEY,
            "Weak certificate key or signature (RSA<2048 or SHA-1)",
            ("2-8-3-3",),
            7.4,
            _TLS_HIGH,
            "Reissue with a 2048-bit or stronger key and a SHA-256 signature.",
        ),
        _spec(
            CheckId.INSECURE_COOKIE,
            "Session cookie without Secure/HttpOnly/SameSite",
            ("2-15-3-3",),
            5.4,
            _HDR_MED,
            "Set Secure, HttpOnly, and SameSite on session cookies.",
        ),
        _spec(
            CheckId.DIRECTORY_LISTING_ENABLED,
            "Directory listing enabled on web server",
            ("2-15-3-3",),
            5.4,
            _HDR_MED,
            "Disable automatic directory indexing on the web server.",
        ),
        _spec(
            CheckId.EXPOSED_SENSITIVE_FILE,
            "Sensitive file exposed (.git, .env, or backup archive)",
            ("2-15-3-3",),
            7.5,
            _PORT_HIGH,
            "Remove exposed source, config, and backup files; block dotfiles at the web server.",
        ),
        _spec(
            CheckId.MISSING_PERMISSIONS_POLICY,
            "Permissions-Policy header absent",
            ("2-15-3-3",),
            3.1,
            _HDR,
            "Set a restrictive Permissions-Policy limiting powerful browser features.",
        ),
        _spec(
            CheckId.EXPOSED_DEV_ENVIRONMENT,
            "Development or staging environment publicly reachable",
            ("2-5-3-2",),
            5.3,
            _PORT_MED,
            "Isolate non-production environments behind a VPN or IP allowlist.",
        ),
        _spec(
            CheckId.DNSSEC_MISSING,
            "DNSSEC not enabled for the domain",
            ("2-5-3-7",),
            3.1,
            _HDR,
            "Enable DNSSEC signing and publish DS records at the registrar.",
        ),
        _spec(
            CheckId.DNS_ZONE_TRANSFER_OPEN,
            "DNS zone transfer (AXFR) allowed to arbitrary clients",
            ("2-5-3-7",),
            7.5,
            _PORT_HIGH,
            "Restrict AXFR to authorized secondary name servers only.",
        ),
        _spec(
            CheckId.NO_DDOS_PROTECTION,
            "No DDoS mitigation fingerprint; origin appears directly exposed",
            ("2-5-3-9", "2-15-3-2"),
            5.3,
            _PORT_MED,
            "Front public services with a DDoS mitigation or CDN provider; hide the origin.",
        ),
        _spec(
            CheckId.EXPOSED_LOGIN_PANEL,
            "Administrative login interface exposed without access control",
            ("2-15-3-5",),
            5.3,
            _PORT_MED,
            "Place admin interfaces behind a VPN and enforce multi-factor authentication.",
        ),
        _spec(
            CheckId.EXPOSED_DATABASE_PORT,
            "Database service port reachable from the internet",
            ("2-5-3-1",),
            7.5,
            _PORT_HIGH,
            "Move databases to a private network segment; never expose them to the internet.",
        ),
        _spec(
            CheckId.EOL_SOFTWARE_EXPOSED,
            "End-of-life, unsupported software version exposed",
            ("2-3-3-3",),
            7.5,
            _PORT_HIGH,
            "Upgrade to a vendor-supported release; establish a lifecycle policy.",
        ),
    ]
}


LIVE_CHECKS: frozenset[CheckId] = frozenset(
    {
        CheckId.SPF_MISSING,
        CheckId.DKIM_MISSING,
        CheckId.DMARC_MISSING_OR_NONE,
        CheckId.LEGACY_TLS_VERSION,
        CheckId.WEAK_TLS_CIPHER,
        CheckId.EXPIRED_CERTIFICATE,
        CheckId.MISSING_CSP,
        CheckId.MISSING_HSTS,
        CheckId.MISSING_REFERRER_POLICY,
        CheckId.MISSING_X_CONTENT_TYPE_OPTIONS,
        CheckId.MISSING_X_FRAME_OPTIONS,
        CheckId.EXPOSED_INTERNAL_PORT,
        CheckId.EXPOSED_MANAGEMENT_PORT,
        CheckId.HIGH_RISK_PORT_OPEN,
        CheckId.NO_HTTPS_REDIRECT,
        CheckId.MISSING_PERMISSIONS_POLICY,
        CheckId.INSECURE_COOKIE,
        CheckId.EXPOSED_DEV_ENVIRONMENT,
        CheckId.SELF_SIGNED_CERTIFICATE,
        CheckId.WEAK_CERTIFICATE_KEY,
        CheckId.DNSSEC_MISSING,
        CheckId.MTA_STS_MISSING,
        CheckId.EXPOSED_DATABASE_PORT,
    }
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def build_finding(
    check_id: CheckId,
    *,
    asset: str,
    observed_state: str,
    consent_ref: str,
    source_tool: str,
    tool_version: str,
    finding_id: str | None = None,
    raw_evidence: dict[str, Any] | None = None,
    extra_control_ids: tuple[str, ...] = (),
    now: datetime | None = None,
) -> Finding:
    spec = CATALOG[check_id]
    control_ids = list(dict.fromkeys([*spec.control_ids, *extra_control_ids]))
    return Finding(
        finding_id=finding_id or f"{check_id.value}:{asset}",
        asset=asset,
        source_tool=source_tool,
        tool_version=tool_version,
        raw_evidence=raw_evidence or {},
        observed_state=observed_state,
        cvss_v3_1_vector=spec.cvss_vector,
        cvss_base_score=spec.cvss_score,
        severity=severity_from_cvss(spec.cvss_score),
        control_ids=control_ids,
        evidence_tier=spec.evidence_tier,
        timestamp=now or _utcnow(),
        consent_ref=consent_ref,
    )
