from __future__ import annotations

from dataclasses import dataclass

from p2c.mapping.catalog import CatalogIndex, load_default_index
from p2c.mapping.models import ControlMapping, MappingMethod
from p2c.scanning.catalog import CATALOG as CHECK_CATALOG
from p2c.scanning.catalog import CheckId
from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import Finding


@dataclass(frozen=True)
class MappingRule:

    rule_id: str
    check_id: CheckId
    control_ids: tuple[str, ...]
    rationale: str
    remediation_ref: str
    reviewer_note: str


def _rule(check_id: CheckId, rationale: str, remediation_ref: str, reviewer_note: str) -> MappingRule:
    return MappingRule(
        rule_id=f"MR-{check_id.value}",
        check_id=check_id,
        control_ids=CHECK_CATALOG[check_id].control_ids,
        rationale=rationale,
        remediation_ref=remediation_ref,
        reviewer_note=reviewer_note,
    )


RULES: dict[CheckId, MappingRule] = {
    r.check_id: r
    for r in [
        _rule(
            CheckId.MISSING_HSTS,
            "Absent HSTS permits a first plaintext request but does not show HTTPS unused; a hardening "
            "finding recorded against no control.",
            "RT-HSTS",
            "Confirm the app is HTTPS-only before treating HSTS absence as material.",
        ),
        _rule(
            CheckId.MISSING_CSP,
            "No Content-Security-Policy weakens hardening against injection; no ECC requirement names it.",
            "RT-CSP",
            "CSP tuning is app-specific; flag, do not auto-score as critical.",
        ),
        _rule(
            CheckId.MISSING_X_FRAME_OPTIONS,
            "Missing anti-framing header exposes the app to clickjacking; no ECC requirement names it.",
            "RT-XFO",
            "Frame-ancestors CSP is an acceptable equivalent; reviewer to check.",
        ),
        _rule(
            CheckId.MISSING_X_CONTENT_TYPE_OPTIONS,
            "Absent nosniff allows MIME-type confusion attacks on the web application.",
            "RT-XCTO",
            "Low severity; part of the baseline header set.",
        ),
        _rule(
            CheckId.MISSING_REFERRER_POLICY,
            "No Referrer-Policy leaks navigation context; a hygiene gap no ECC requirement names.",
            "RT-REFPOL",
            "Informational; bundles with the header baseline.",
        ),
        _rule(
            CheckId.NO_HTTPS_REDIRECT,
            "Content served over plain HTTP: no secure protocol (2-15-3-3) and unencrypted transit (2-8-3-3).",
            "RT-HTTPS-REDIR",
            "Verify no plaintext-only legacy endpoint is required before enforcing.",
        ),
        _rule(
            CheckId.LEGACY_TLS_VERSION,
            "TLS 1.0/1.1 is outside the NCS (2-8-3-1), below standard transit encryption (2-8-3-3) and no "
            "secure protocol for a web application (2-15-3-3).",
            "RT-TLS-VERSION",
            "Confirm no legacy client dependency before disabling.",
        ),
        _rule(
            CheckId.WEAK_TLS_CIPHER,
            "A NULL, anonymous, export, MD5, RC4 or DES suite is outside the NCS (2-8-3-1), below standard "
            "transit encryption (2-8-3-3) and no secure protocol for a web application (2-15-3-3).",
            "RT-TLS-CIPHER",
            "Map negotiated cipher to NCA-approved list.",
        ),
        _rule(
            CheckId.EXPIRED_CERTIFICATE,
            "A certificate in service past its validity shows the key lifecycle unmanaged (2-8-3-2) and leaves "
            "HTTPS failing for clients (2-15-3-3).",
            "RT-CERT",
            "Distinguish expiry from chain/hostname mismatch in evidence.",
        ),
        _rule(
            CheckId.WAF_ABSENT,
            "No WAF signature on ordinary responses; a passive read cannot show a WAF absent, so no control.",
            "RT-WAF",
            "Fingerprinting is probabilistic; record confidence, needs review.",
        ),
        _rule(
            CheckId.EXPOSED_INTERNAL_PORT,
            "Internal service reachable from the internet breaks segmentation and the restriction of "
            "services and ports.",
            "RT-SEGMENT",
            "Confirm the port is genuinely internal-only by design.",
        ),
        _rule(
            CheckId.EXPOSED_MANAGEMENT_PORT,
            "A management port open to the internet shows services and ports not restricted (2-5-3-5).",
            "RT-MGMT-PORT",
            "Check for a VPN/MFA gateway in front before scoring.",
        ),
        _rule(
            CheckId.HIGH_RISK_PORT_OPEN,
            "A legacy or plaintext service port (Telnet, FTP, SMB) open to the internet shows services and "
            "ports not restricted (2-5-3-5).",
            "RT-PORT-RESTRICT",
            "Reconcile against the entity's approved-exception list.",
        ),
        _rule(
            CheckId.OUTDATED_EXPOSED_SOFTWARE,
            "A banner lacking a patch released more than three months earlier, the longest cycle the NCA's "
            "patch management template allows applications, shows a released patch not applied "
            "(2-3-3-3, 2-10-3-4).",
            "RT-PATCH",
            "Cross-check the banner version against the CVE before asserting.",
        ),
        _rule(
            CheckId.SPF_MISSING,
            "Missing/broken SPF fails the SPF/DKIM/DMARC email-domain validation control.",
            "RT-SPF",
            "Distinguish absent from present-but-permissive (+all).",
        ),
        _rule(
            CheckId.DMARC_MISSING_OR_NONE,
            "DMARC absent or policy=none is non-enforcement; email-domain validation control is unmet.",
            "RT-DMARC",
            "policy=none counts as non-enforcing for scoring.",
        ),
        _rule(
            CheckId.DKIM_MISSING,
            "No DKIM key at the probed selectors; selectors cannot be listed, so DKIM is not shown unused.",
            "RT-DKIM",
            "Selector-limited: a negative may be a false negative; needs onboarding selectors.",
        ),
        _rule(
            CheckId.MTA_STS_MISSING,
            "No MTA-STS policy leaves inbound SMTP open to downgrade; not domain validation, so no control.",
            "RT-MTA-STS",
            "Bundle with SPF/DKIM/DMARC review; low severity on its own.",
        ),
        _rule(
            CheckId.SELF_SIGNED_CERTIFICATE,
            "A self-signed certificate on a public web application leaves HTTPS without trust (2-15-3-3); "
            "the NCS asks that a trusted CA certify the key (2-8-3-2).",
            "RT-CERT-TRUST",
            "Distinguish a genuinely untrusted chain from a private-CA endpoint before scoring.",
        ),
        _rule(
            CheckId.WEAK_CERTIFICATE_KEY,
            "A certificate key below the NCS line (RSA under 3072 bits, DSA, or an unaccepted curve) is "
            "outside the NCS (2-8-3-1) and was created below strength (2-8-3-2).",
            "RT-CERT-KEY",
            "Record the observed key algorithm and size as evidence.",
        ),
        _rule(
            CheckId.INSECURE_COOKIE,
            "Session cookie without Secure/HttpOnly/SameSite weakens hardening; no ECC requirement names it.",
            "RT-COOKIE",
            "Confirm the cookie is session-bearing before treating it as material.",
        ),
        _rule(
            CheckId.DIRECTORY_LISTING_ENABLED,
            "Directory listing discloses server contents; a hardening gap no ECC requirement names.",
            "RT-DIRLIST",
            "Verify the listing is unintended, not a deliberate open index.",
        ),
        _rule(
            CheckId.EXPOSED_SENSITIVE_FILE,
            "Exposed .git/.env/backup leaks source or secrets; a hardening gap no ECC requirement names.",
            "RT-SENSFILE",
            "Confirm the artifact is genuinely sensitive, not a decoy or empty path.",
        ),
        _rule(
            CheckId.MISSING_PERMISSIONS_POLICY,
            "Absent Permissions-Policy leaves browser features unrestricted; no ECC requirement names it.",
            "RT-PERMPOL",
            "Informational; part of the modern header baseline.",
        ),
        _rule(
            CheckId.EXPOSED_DEV_ENVIRONMENT,
            "A development-grade server or debug profiler answers; it shows neither an environment nor a network, "
            "so no control.",
            "RT-DEVENV",
            "Confirm the environment is non-production, not a mislabeled production host.",
        ),
        _rule(
            CheckId.DNSSEC_MISSING,
            "No DNSSEC leaves resolution open to spoofing; DNS security requirement (2-5-3-7).",
            "RT-DNSSEC",
            "Registrar/zone dependent; record whether the parent zone supports DS.",
        ),
        _rule(
            CheckId.DNS_ZONE_TRANSFER_OPEN,
            "Open AXFR discloses the full zone; DNS security requirement unmet (2-5-3-7).",
            "RT-AXFR",
            "High confidence when AXFR returns records; verify against each authoritative NS.",
        ),
        _rule(
            CheckId.NO_DDOS_PROTECTION,
            "No DDoS-mitigation fingerprint; upstream scrubbing is invisible, so protection is not shown absent.",
            "RT-DDOS",
            "Fingerprint absence is probabilistic; record confidence, needs review.",
        ),
        _rule(
            CheckId.EXPOSED_LOGIN_PANEL,
            "A login form at a common path shows authentication exists, not that it is inadequate; no control.",
            "RT-LOGIN",
            "Check for a VPN/SSO gateway or MFA before scoring as a gap.",
        ),
        _rule(
            CheckId.EXPOSED_DATABASE_PORT,
            "An internet-reachable database port breaks network isolation (2-5-3-1) and port "
            "restriction (2-5-3-5).",
            "RT-DB-PORT",
            "Confirm the port is a live database service, not a honeypot or filtered response.",
        ),
        _rule(
            CheckId.EOL_SOFTWARE_EXPOSED,
            "End-of-life software gets no patches: patch management (2-3-3-3, 2-10-3-4) cannot be met for it.",
            "RT-EOL",
            "Cross-check the banner version against the vendor lifecycle before asserting.",
        ),
        _rule(
            CheckId.EXPOSED_PRINTER_SERVICE,
            "A print service open to the internet shows the printer's use not secured (2-7-1-3), "
            "segmentation not in place (2-5-3-1) and a service and port not restricted (2-5-3-5).",
            "RT-PRINTER",
            "Number-only read: confirm the port is a print service before asserting.",
        ),
    ]
}


def check_id_from_finding(finding: Finding) -> CheckId | None:
    head = finding.finding_id.split(":", 1)[0]
    try:
        return CheckId(head)
    except ValueError:
        return None


def validate_rules(index: CatalogIndex) -> None:
    for rule in RULES.values():
        for cid in rule.control_ids:
            if not index.is_valid(cid):
                raise ValueError(
                    f"rule {rule.rule_id} references control {cid!r} absent from the OSCAL catalog"
                )


class MappingEngine:

    def __init__(self, index: CatalogIndex | None = None) -> None:
        self._index = index or load_default_index()
        validate_rules(self._index)

    def map_finding(self, finding: Finding) -> list[ControlMapping]:
        check_id = check_id_from_finding(finding)
        rule = RULES.get(check_id) if check_id is not None else None
        rule_ids = rule.control_ids if rule is not None else ()
        ordered_ids = list(dict.fromkeys([*rule_ids, *finding.control_ids]))
        mappings: list[ControlMapping] = []
        for cid in ordered_ids:
            entry = self._index.get(cid)
            if entry is None:
                continue
            if rule is not None and cid in rule_ids:
                rule_id, rationale = rule.rule_id, rule.rationale
                spec = CHECK_CATALOG.get(rule.check_id)
                remediation = (spec.remediation if spec else "") or entry.remediation_en
                reviewer_note = rule.reviewer_note
            else:
                rule_id, rationale = None, "catalog-tagged finding"
                remediation, reviewer_note = entry.remediation_en, ""
            mappings.append(
                ControlMapping(
                    control_id=cid,
                    framework=entry.framework,
                    tier=EvidenceTier(entry.tier),
                    finding_id=finding.finding_id,
                    asset=finding.asset,
                    severity=finding.severity,
                    method=MappingMethod.DETERMINISTIC,
                    confidence=1.0,
                    rule_id=rule_id,
                    rationale=rationale,
                    remediation=remediation,
                    reviewer_note=reviewer_note,
                    ncnicc_class_a=entry.ncnicc_class_a,
                    ncnicc_class_b=entry.ncnicc_class_b,
                    ncnicc_class_a_status=entry.ncnicc_class_a_status,
                    ncnicc_class_b_status=entry.ncnicc_class_b_status,
                    needs_confirmation=False,
                    timestamp=finding.timestamp,
                )
            )
        return mappings

    def map_findings(self, findings: list[Finding]) -> list[ControlMapping]:
        out: list[ControlMapping] = []
        for finding in findings:
            out.extend(self.map_finding(finding))
        out.sort(key=lambda m: (m.control_id, m.asset, m.finding_id))
        return out
