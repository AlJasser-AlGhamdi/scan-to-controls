import re
from pathlib import Path

from p2c import scanning
from p2c.evaluation.harness import LIVE_INSPECTOR_CHECKS
from p2c.scanning.catalog import LIVE_CHECKS, CheckId

_INSPECTOR_MODULES = (
    "email_dns",
    "tls",
    "headers",
    "ports",
    "httpx_probe",
    "nuclei",
    "dns_sec",
    "mta_sts",
    "services",
)


def test_live_checks_match_inspector_sources() -> None:
    src = Path(scanning.__file__).parent
    emitted: set[str] = set()
    for mod in _INSPECTOR_MODULES:
        text = (src / f"{mod}.py").read_text(encoding="utf-8")
        emitted |= set(re.findall(r"CheckId\.([A-Z_]+)", text))
    assert {c.name for c in LIVE_CHECKS} == emitted


def test_live_checks_are_catalog_members() -> None:
    assert set(CheckId) >= LIVE_CHECKS
    assert len(LIVE_CHECKS) == 23


def test_the_implemented_only_slice_reads_the_same_live_set() -> None:
    assert {check.value for check in LIVE_CHECKS} == LIVE_INSPECTOR_CHECKS
