from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import structlog
from pydantic import Field

from p2c.authz.audit import AuditLog
from p2c.authz.gate import OwnershipNotVerified, ScanBlocked, require_verified_ownership
from p2c.authz.guardrails import RateLimiter, ScopeEnforcer
from p2c.authz.repositories import ConsentRepository, VerificationRepository
from p2c.hosts import candidate_apexes
from p2c.hosts import canonical_host as _norm
from p2c.scanning.catalog import CheckId, build_finding
from p2c.schemas.enums import AuditEventType
from p2c.schemas.models import AtlasModel, Finding
from p2c.sovereignty.egress_guard import caused_by_egress_block

log = structlog.get_logger("p2c.scanning")


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ScanResult(AtlasModel):

    target: str
    verification_id: str
    findings: list[Finding]
    errors: list[str] = Field(default_factory=list)


SourceFn = Callable[[str], list[CheckId]]
NucleiFn = Callable[[str, str, "datetime | None"], list[Finding]]


class ScanEngine:

    def __init__(
        self,
        *,
        verifications: VerificationRepository,
        consents: ConsentRepository | None = None,
        audit: AuditLog | None = None,
        header_source: SourceFn | None = None,
        tls_source: SourceFn | None = None,
        email_source: SourceFn | None = None,
        port_source: SourceFn | None = None,
        nuclei_findings: NucleiFn | None = None,
        rate_limiter: RateLimiter | None = None,
        clock: Callable[[], datetime] | None = None,
        source_tool: str = "atlas-scan",
        tool_version: str = "0.0.0",
        actor: str = "atlas-scan",
    ) -> None:
        self._verifications = verifications
        self._consents = consents
        self._audit = audit
        self._sources: list[tuple[str, SourceFn]] = [
            (name, fn)
            for name, fn in (
                ("http-headers", header_source),
                ("tls", tls_source),
                ("email-dns", email_source),
                ("ports", port_source),
            )
            if fn is not None
        ]
        self._nuclei = nuclei_findings
        self._rate_limiter = rate_limiter
        self._clock = clock or _utcnow
        self._source_tool = source_tool
        self._tool_version = tool_version
        self._actor = actor

    def scan(self, target: str, *, consent_ref: str) -> ScanResult:
        now = self._clock()
        target = _norm(target)

        try:
            verification = require_verified_ownership(target, verifications=self._verifications, at=now)
        except OwnershipNotVerified:
            self._audit_block(target, "ownership_not_verified")
            raise

        consent_id = self._enforce_consent(target, now)

        if self._rate_limiter is not None and not self._rate_limiter.allow(target):
            self._audit_block(target, "rate_limited")
            raise ScanBlocked(target, "rate limit exceeded")

        effective_ref = consent_id or consent_ref
        findings, errors = self._run_sources(target, effective_ref, now)

        findings.sort(key=lambda f: (f.asset, f.control_ids[0] if f.control_ids else "", f.finding_id))
        self._audit_event(
            AuditEventType.SCAN_AUTHORIZED,
            target,
            {"verification_id": verification.verification_id, "findings": len(findings)},
        )
        return ScanResult(
            target=target,
            verification_id=verification.verification_id,
            findings=findings,
            errors=errors,
        )

    def _enforce_consent(self, target: str, now: datetime) -> str:
        if self._consents is None:
            return ""
        consent = next(
            (c for apex in candidate_apexes(target) if (c := self._consents.for_apex(apex)) is not None),
            None,
        )
        if consent is None:
            self._audit_block(target, "no_consent")
            raise ScanBlocked(target, "no consent record for target")
        if not consent.is_active(now):
            self._audit_block(target, "consent_window_inactive")
            raise ScanBlocked(target, "consent window is not active")
        if not ScopeEnforcer(consent).is_in_scope(target):
            self._audit_block(target, "out_of_scope")
            raise ScanBlocked(target, "target is out of consent scope")
        return consent.consent_id

    def _run_sources(self, target: str, consent_ref: str, now: datetime) -> tuple[list[Finding], list[str]]:
        findings: list[Finding] = []
        errors: list[str] = []
        for name, source in self._sources:
            try:
                for check in source(target):
                    findings.append(self._finding(check, target, consent_ref, name, now))
            except Exception as exc:
                if caused_by_egress_block(exc):
                    raise
                log.warning("scan_source_failed", source=name, error=str(exc))
                errors.append(f"{name}: {exc}")

        if self._nuclei is not None:
            try:
                findings.extend(self._nuclei(target, consent_ref, now))
            except Exception as exc:
                if caused_by_egress_block(exc):
                    raise
                errors.append(f"nuclei: {exc}")
        return findings, errors

    def _finding(self, check: CheckId, target: str, consent_ref: str, source: str, now: datetime) -> Finding:
        return build_finding(
            check,
            asset=target,
            observed_state=f"{check.value} detected on {target} ({source})",
            consent_ref=consent_ref,
            source_tool=f"{self._source_tool}:{source}",
            tool_version=self._tool_version,
            now=now,
        )

    def _audit_block(self, target: str, reason: str) -> None:
        self._audit_event(AuditEventType.SCAN_BLOCKED, target, {"reason": reason})

    def _audit_event(self, event: AuditEventType, target: str, payload: dict[str, object]) -> None:
        if self._audit is not None:
            self._audit.append(event, actor=self._actor, target=target, payload=payload)
