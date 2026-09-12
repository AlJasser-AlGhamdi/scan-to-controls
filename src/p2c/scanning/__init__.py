from __future__ import annotations

from pathlib import Path

from p2c.scanning.catalog import CATALOG, CheckId, CheckSpec, build_finding
from p2c.scanning.dns_sec import DnspythonResolver, DnssecInspector, DnssecResult, RecordResolver
from p2c.scanning.email_dns import (
    DKIM_SELECTORS,
    DnsReadIndeterminate,
    DnsRecordAbsent,
    EmailDnsInspector,
    EmailDnsResult,
)
from p2c.scanning.headers import analyze_security_headers
from p2c.scanning.httpx_probe import (
    HttpProbe,
    checks_for_probe,
    dev_environment_signature,
    parse_httpx,
    response_received,
)
from p2c.scanning.mta_sts import MtaStsInspector, MtaStsResult, MtaStsState
from p2c.scanning.nuclei import NucleiResult, NucleiRunner, parse_nuclei
from p2c.scanning.ports import classify_port, parse_naabu
from p2c.scanning.services import ServiceInspector, ServiceProbe, checks_for_service, identify_database
from p2c.scanning.signing import TemplateSigner, sign_bytes, verify_bytes
from p2c.scanning.tls import TlsInfo, TlsInspector, evaluate_tls

TEMPLATES_DIR = Path(__file__).parent / "templates"

__all__ = [
    "CATALOG",
    "DKIM_SELECTORS",
    "TEMPLATES_DIR",
    "CheckId",
    "CheckSpec",
    "DnsReadIndeterminate",
    "DnsRecordAbsent",
    "DnspythonResolver",
    "DnssecInspector",
    "DnssecResult",
    "EmailDnsInspector",
    "EmailDnsResult",
    "HttpProbe",
    "MtaStsInspector",
    "MtaStsResult",
    "MtaStsState",
    "NucleiResult",
    "NucleiRunner",
    "RecordResolver",
    "ServiceInspector",
    "ServiceProbe",
    "TemplateSigner",
    "TlsInfo",
    "TlsInspector",
    "analyze_security_headers",
    "build_finding",
    "checks_for_probe",
    "checks_for_service",
    "classify_port",
    "dev_environment_signature",
    "evaluate_tls",
    "identify_database",
    "parse_httpx",
    "parse_naabu",
    "parse_nuclei",
    "response_received",
    "sign_bytes",
    "verify_bytes",
]
