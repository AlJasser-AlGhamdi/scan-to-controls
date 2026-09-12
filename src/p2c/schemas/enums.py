from __future__ import annotations

from enum import IntEnum, StrEnum


class RunMode(StrEnum):
    LIVE = "LIVE"
    SYNTHETIC = "SYNTHETIC"


class Severity(StrEnum):

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceTier(IntEnum):
    TIER_1 = 1
    TIER_2 = 2
    TIER_3 = 3


class ScanIntensity(StrEnum):

    PASSIVE = "PASSIVE"
    SAFE_ACTIVE = "SAFE_ACTIVE"
    FULL_ACTIVE = "FULL_ACTIVE"


class Framework(StrEnum):

    ECC_2_2024 = "ECC-2:2024"
    NCNICC_1_2025 = "NCNICC-1:2025"


class ChallengeType(StrEnum):

    DNS_TXT = "dns-txt"
    HTML_FILE = "html-file"
    META_TAG = "meta-tag"


class VerificationStatus(StrEnum):

    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class AuditEventType(StrEnum):

    CHALLENGE_ISSUED = "challenge_issued"
    OWNERSHIP_VERIFIED = "ownership_verified"
    OWNERSHIP_FAILED = "ownership_failed"
    CONSENT_GRANTED = "consent_granted"
    CONSENT_REVOKED = "consent_revoked"
    SCAN_AUTHORIZED = "scan_authorized"
    SCAN_BLOCKED = "scan_blocked"
    ATTESTATION_ISSUED = "attestation_issued"
    ATTESTATION_RENEWED = "attestation_renewed"


class AssetType(StrEnum):

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    SERVICE = "service"


class DiscoveryMethod(StrEnum):

    SUBFINDER = "subfinder"
    AMASS_PASSIVE = "amass-passive"
    CRTSH = "crt.sh"
    DNSX = "dnsx"
    SYNTHETIC = "synthetic"
