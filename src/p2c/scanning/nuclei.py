from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import structlog

from p2c.discovery.runner import CommandRunner
from p2c.scanning.catalog import CheckId, _utcnow, build_finding, is_valid_control_id
from p2c.scanning.signing import TemplateSigner
from p2c.schemas.enums import EvidenceTier, Severity
from p2c.schemas.models import Finding, severity_from_cvss

log = structlog.get_logger("p2c.scanning.nuclei")

NUCLEI_VERSION = "v3.10.0"

_NUCLEI_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.NONE,
}
_CHECK_VALUES = {c.value for c in CheckId}
_CVSS_MIN, _CVSS_MAX = 0.0, 10.0


@dataclass(frozen=True)
class NucleiResult:

    template_id: str
    host: str
    matched_at: str
    severity: str
    check_id: str | None = None
    control_ids: tuple[str, ...] = field(default_factory=tuple)
    cvss_vector: str | None = None
    cvss_score: float | None = None


def _as_control_ids(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        candidates = [str(v).strip() for v in value]
    elif isinstance(value, str):
        candidates = [part.strip() for part in value.split(",")]
    else:
        return ()
    valid = tuple(c for c in candidates if c and is_valid_control_id(c))
    dropped = [c for c in candidates if c and not is_valid_control_id(c)]
    if dropped:
        log.warning("nuclei_dropped_invalid_control_ids", dropped=dropped)
    return valid


def parse_nuclei(output: str) -> list[NucleiResult]:
    results: list[NucleiResult] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        info_raw = obj.get("info")
        info: dict[str, object] = info_raw if isinstance(info_raw, dict) else {}
        meta_raw = info.get("metadata")
        metadata: dict[str, object] = meta_raw if isinstance(meta_raw, dict) else {}
        cls_raw = info.get("classification")
        classification: dict[str, object] = cls_raw if isinstance(cls_raw, dict) else {}
        raw_check_id = metadata.get("atlas-check-id")
        cvss_vector = classification.get("cvss-metrics")
        cvss_score = classification.get("cvss-score")
        results.append(
            NucleiResult(
                template_id=str(obj.get("template-id", "")),
                host=str(obj.get("host", "")),
                matched_at=str(obj.get("matched-at", "")),
                severity=str(info.get("severity", "")),
                check_id=raw_check_id if isinstance(raw_check_id, str) else None,
                control_ids=_as_control_ids(metadata.get("control-id")),
                cvss_vector=cvss_vector if isinstance(cvss_vector, str) else None,
                cvss_score=float(cvss_score) if isinstance(cvss_score, int | float) else None,
            )
        )
    return results


class NucleiRunner:

    def __init__(
        self,
        runner: CommandRunner,
        signer: TemplateSigner,
        *,
        version: str = NUCLEI_VERSION,
        timeout: float = 300.0,
    ) -> None:
        self._runner = runner
        self._signer = signer
        self.version = version
        self._timeout = timeout

    def run(
        self,
        target: str,
        template_dir: Path,
        *,
        consent_ref: str,
        now: datetime | None = None,
    ) -> list[Finding]:
        verified = self._signer.verified_templates(template_dir)
        if not verified:
            raise ValueError(f"no signed nuclei templates in {template_dir} (all unsigned/tampered)")
        argv = ["nuclei", "-jsonl", "-silent", "-duc", "-u", target]
        for path in verified:
            argv += ["-t", str(path)]
        result = self._runner.run(argv, timeout=self._timeout)
        return [self._to_finding(r, target, consent_ref, now) for r in parse_nuclei(result.stdout)]

    def _to_finding(
        self, result: NucleiResult, asset: str, consent_ref: str, now: datetime | None
    ) -> Finding:
        raw_evidence = {
            "template_id": result.template_id,
            "matched_at": result.matched_at,
            "host": result.host,
        }
        if result.check_id is not None and result.check_id in _CHECK_VALUES:
            return build_finding(
                CheckId(result.check_id),
                asset=asset,
                observed_state=f"nuclei template {result.template_id} matched at {result.matched_at}",
                consent_ref=consent_ref,
                source_tool="nuclei",
                tool_version=self.version,
                raw_evidence=raw_evidence,
                extra_control_ids=result.control_ids,
                now=now,
            )
        return _generic_finding(result, asset, consent_ref, self.version, now)


def _generic_finding(
    result: NucleiResult, asset: str, consent_ref: str, version: str, now: datetime | None
) -> Finding:
    if result.cvss_score is not None and _CVSS_MIN <= result.cvss_score <= _CVSS_MAX:
        severity = severity_from_cvss(result.cvss_score)
    else:
        severity = _NUCLEI_SEVERITY.get(result.severity.lower(), Severity.NONE)
    return Finding(
        finding_id=f"{result.template_id}:{asset}",
        asset=asset,
        source_tool="nuclei",
        tool_version=version,
        raw_evidence={"template_id": result.template_id, "matched_at": result.matched_at},
        observed_state=f"nuclei template {result.template_id} matched",
        cvss_v3_1_vector=result.cvss_vector,
        cvss_base_score=result.cvss_score if result.cvss_score is not None else None,
        severity=severity,
        control_ids=list(result.control_ids),
        evidence_tier=EvidenceTier.TIER_1,
        timestamp=now or _utcnow(),
        consent_ref=consent_ref,
    )
