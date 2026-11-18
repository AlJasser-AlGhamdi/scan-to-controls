from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import httpx

from p2c.evaluation import metrics as M
from p2c.scanning.banners import BannerState, evaluate_banners
from p2c.scanning.catalog import CheckId
from p2c.scanning.dns_axfr import ZoneTransferInspector
from p2c.scanning.dns_sec import DnspythonResolver
from p2c.scanning.email_dns import EmailDnsInspector
from p2c.scanning.fingerprints import DdosInspector, waf_checks
from p2c.scanning.httpx_probe import HttpProbe, checks_for_probe
from p2c.scanning.tls import TlsInspector, evaluate_tls
from p2c.scanning.web_paths import PathState, WebPathInspector

HTTP_BASE = "http://127.0.0.1:9080"
BANNER_BASE = "http://127.0.0.1:9081"
TLS_HOST = "127.0.0.1"
DNS_SERVER, DNS_PORT = "127.0.0.1", 9053
SCAN_DATE = date(2026, 10, 14)


@dataclass(frozen=True)
class Case:

    name: str
    expected: frozenset[CheckId]
    unreadable: str | None = None
    declared_false_positive: str | None = None


_HTTP_CASES: dict[str, Case] = {
    "/": Case(
        "no security headers",
        frozenset(
            {
                CheckId.MISSING_HSTS,
                CheckId.MISSING_CSP,
                CheckId.MISSING_X_FRAME_OPTIONS,
                CheckId.MISSING_X_CONTENT_TYPE_OPTIONS,
                CheckId.MISSING_REFERRER_POLICY,
                CheckId.MISSING_PERMISSIONS_POLICY,
            }
        ),
    ),
    "/clean": Case("every header present", frozenset()),
    "/no-permissions-policy": Case(
        "only Permissions-Policy absent", frozenset({CheckId.MISSING_PERMISSIONS_POLICY})
    ),
    "/cookie-insecure": Case("a cookie without Secure", frozenset({CheckId.INSECURE_COOKIE})),
    "/cookie-secure": Case("every cookie has Secure", frozenset()),
    "/dev-server": Case("development server signature", frozenset({CheckId.EXPOSED_DEV_ENVIRONMENT})),
    "/dev-name-only": Case("development hostname, production server", frozenset()),
}

_TLS_CASES: dict[int, Case] = {
    9443: Case("self-signed RSA-3072", frozenset({CheckId.SELF_SIGNED_CERTIFICATE})),
    9444: Case("private-CA leaf, untrusted but not self-signed", frozenset()),
    9445: Case(
        "self-signed RSA-2048, below the NCS line",
        frozenset({CheckId.SELF_SIGNED_CERTIFICATE, CheckId.WEAK_CERTIFICATE_KEY}),
    ),
    9446: Case("self-signed RSA-4096", frozenset({CheckId.SELF_SIGNED_CERTIFICATE})),
    9447: Case("self-signed EC P-256", frozenset({CheckId.SELF_SIGNED_CERTIFICATE})),
    9448: Case(
        "self-signed EC secp192r1",
        frozenset({CheckId.SELF_SIGNED_CERTIFICATE, CheckId.WEAK_CERTIFICATE_KEY}),
        unreadable="declared blind spot: the scanner's TLS stack cannot negotiate this curve",
    ),
    9449: Case(
        "expired self-signed RSA-3072",
        frozenset({CheckId.EXPIRED_CERTIFICATE, CheckId.SELF_SIGNED_CERTIFICATE}),
    ),
}


_DIR, _SENS, _LOGIN = (
    CheckId.DIRECTORY_LISTING_ENABLED,
    CheckId.EXPOSED_SENSITIVE_FILE,
    CheckId.EXPOSED_LOGIN_PANEL,
)
_PATH_CASES: dict[str, Case] = {
    "/case-dir-pos": Case("auto-generated directory index", frozenset({_DIR})),
    "/case-dir-neg": Case("directory with listing disabled", frozenset()),
    "/case-dir-mention": Case("a page that only mentions an index", frozenset()),
    "/case-sens-git": Case("a leaked .git/HEAD", frozenset({_SENS})),
    "/case-sens-env": Case("a leaked .env", frozenset({_SENS})),
    "/case-sens-dsstore": Case("a leaked .DS_Store", frozenset({_SENS})),
    "/case-sens-sql": Case("a leaked SQL dump", frozenset({_SENS})),
    "/case-sens-status": Case("an exposed Apache status page", frozenset({_SENS})),
    "/case-sens-phpinfo": Case("an exposed phpinfo page", frozenset({_SENS})),
    "/case-sens-soft404": Case("soft 404 on every path", frozenset()),
    "/case-login-pos": Case("a password form at /admin/", frozenset({_LOGIN})),
    "/case-login-auth": Case("an authentication challenge at /manager/html", frozenset({_LOGIN})),
    "/case-login-search": Case("a form without a password field", frozenset()),
    "/case-login-everywhere": Case(
        "a login widget on every path, nonexistent ones too",
        frozenset(),
        unreadable="contract: a login served on every path neither shows nor rules out a panel",
    ),
}
_BANNER_CASES: dict[str, Case] = {
    "/current": Case("current nginx banner", frozenset()),
    "/outdated": Case(
        "older patch of a supported nginx cycle, a patch missed past three months",
        frozenset({CheckId.OUTDATED_EXPOSED_SOFTWARE}),
    ),
    "/outdated-recent": Case("older patch, missing only a patch released within three months", frozenset()),
    "/eol": Case("Apache 2.2 banner, cycle ended", frozenset({CheckId.EOL_SOFTWARE_EXPOSED})),
    "/php-eol": Case("PHP 8.1 X-Powered-By, cycle ended", frozenset({CheckId.EOL_SOFTWARE_EXPOSED})),
    "/hidden": Case(
        "product named without a version", frozenset(), unreadable="contract: no version is unread"
    ),
    "/cycle-only": Case(
        "supported cycle named without a patch level",
        frozenset(),
        unreadable="contract: no patch level is unread",
    ),
}
_WAF_CASES: dict[str, Case] = {
    "/case-waf-cf": Case("Cloudflare ray header", frozenset()),
    "/case-waf-cookie": Case("Imperva session cookie", frozenset()),
    "/case-waf-none": Case("bare origin", frozenset({CheckId.WAF_ABSENT})),
}
_AXFR_CASES: dict[str, Case] = {
    "axfr-open.test": Case("zone transfer allowed to anyone", frozenset({CheckId.DNS_ZONE_TRANSFER_OPEN})),
    "axfr-closed.test": Case("zone transfer refused", frozenset()),
}
_EMAIL = (CheckId.SPF_MISSING, CheckId.DMARC_MISSING_OR_NONE, CheckId.DKIM_MISSING)
_EMAIL_CASES: dict[str, Case] = {
    "email-good.test": Case("SPF, DMARC reject and a DKIM key split over two strings", frozenset()),
    "email-nospf.test": Case("no SPF record beside another TXT record", frozenset({CheckId.SPF_MISSING})),
    "email-dmarc-none.test": Case("DMARC policy none", frozenset({CheckId.DMARC_MISSING_OR_NONE})),
    "email-nodmarc.test": Case("no DMARC record", frozenset({CheckId.DMARC_MISSING_OR_NONE})),
    "email-nodkim.test": Case("no DKIM key at any selector", frozenset({CheckId.DKIM_MISSING})),
    "email-selector1.test": Case("DKIM key at a catalogued non-default selector", frozenset()),
    "email-oddselector.test": Case(
        "DKIM key at a selector outside the catalogue",
        frozenset(),
        declared_false_positive="selector limit: a key the scan cannot name reads as missing",
    ),
}
_DDOS_CASES: dict[str, Case] = {
    "ddos-ns.test": Case(
        "provider name servers alone",
        frozenset(),
        unreadable="contract: name servers alone do not show that traffic passes the provider's edge",
    ),
    "ddos-cname.test": Case("www aliased to a provider edge", frozenset()),
    "ddos-plain.test": Case(
        "no provider in name servers or aliases", frozenset({CheckId.NO_DDOS_PROTECTION})
    ),
}


def _get(path: str) -> httpx.Response | None:
    try:
        return httpx.get(f"{HTTP_BASE}{path}", timeout=5.0)
    except httpx.HTTPError:
        return None


def _path_checks(base: str) -> set[CheckId] | None:
    inspector = WebPathInspector()
    results = (
        inspector.directory_listing(f"{HTTP_BASE}{base}"),
        inspector.sensitive_files(f"{HTTP_BASE}{base}"),
        inspector.login_panel(f"{HTTP_BASE}{base}"),
    )
    unread = {r.check for r in results if r.state is PathState.UNREAD}
    if _PATH_AXIS[base.split("-")[1]] in unread:
        return None
    _NOT_READ.setdefault(base, set()).update(unread)
    return {c for r in results for c in r.checks}


_PATH_AXIS = {"dir": _DIR, "sens": _SENS, "login": _LOGIN}


_NOT_READ: dict[str, set[CheckId]] = {}


def _banner_checks(path: str) -> set[CheckId] | None:
    try:
        response = httpx.get(f"{BANNER_BASE}{path}", timeout=5.0)
    except httpx.HTTPError:
        response = None
    if response is None:
        return None
    result = evaluate_banners(dict(response.headers), today=SCAN_DATE)
    if result.state is not BannerState.READ:
        return None
    _NOT_READ.setdefault(path, set()).update(result.unread)
    return set(result.checks)


def _waf_checks(path: str) -> set[CheckId] | None:
    response = _get(path)
    if response is None:
        return None
    cookies = tuple(v for k, v in response.headers.multi_items() if k.lower() == "set-cookie")
    probe = HttpProbe(
        url=str(response.url),
        host=TLS_HOST,
        scheme="https",
        status_code=response.status_code,
        headers=dict(response.headers),
        set_cookie=cookies,
    )
    return set(waf_checks(probe))


def _resolver() -> DnspythonResolver:
    return DnspythonResolver(nameservers=[DNS_SERVER], port=DNS_PORT)


def _axfr_checks(zone: str) -> set[CheckId] | None:
    result = ZoneTransferInspector(_resolver(), port=DNS_PORT, allow_internal=True).inspect_detailed(zone)
    return set(result.checks) if result.read else None


def _email_checks(zone: str) -> set[CheckId] | None:
    result = EmailDnsInspector(_resolver()).inspect_detailed(zone)
    return None if result.indeterminate else set(result.checks)


def _ddos_checks(zone: str) -> set[CheckId] | None:
    result = DdosInspector(_resolver()).inspect_detailed(zone)
    return set(result.checks) if result.read else None


def _http_checks(path: str) -> set[CheckId] | None:
    try:
        response = httpx.get(f"{HTTP_BASE}{path}", timeout=5.0)
    except httpx.HTTPError:
        return None
    cookies = tuple(v for k, v in response.headers.multi_items() if k.lower() == "set-cookie")
    probe = HttpProbe(
        url=str(response.url),
        host=TLS_HOST,
        scheme="https",
        status_code=response.status_code,
        headers=dict(response.headers),
        set_cookie=cookies,
    )
    return set(checks_for_probe(probe))


def _tls_checks(port: int) -> set[CheckId] | None:
    try:
        return set(evaluate_tls(TlsInspector().inspect(TLS_HOST, port)))
    except OSError:
        return None


def _score(
    trials: list[set[CheckId] | None], expected: frozenset[CheckId], universe: set[CheckId]
) -> dict[str, Any]:
    read = [t for t in trials if t is not None]
    counts = {c: sum(1 for t in read if c in t) for c in universe}
    return {
        "trials": len(trials),
        "unreadable": len(trials) - len(read),
        "expected": sorted(c.value for c in expected),
        "fired": {c.value: n for c, n in counts.items() if n},
    }


def measure(k: int = 60) -> dict[str, Any]:
    http_universe = set().union(*(c.expected for c in _HTTP_CASES.values())) or set()
    tls_universe = set().union(*(c.expected for c in _TLS_CASES.values())) or set()
    cases: dict[str, Any] = {}
    per_detector: dict[CheckId, dict[str, int]] = {}

    def _accumulate(
        expected: frozenset[CheckId], universe: set[CheckId], trials: list[set[CheckId] | None]
    ) -> None:
        for check in universe:
            slot = per_detector.setdefault(check, {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
            for outcome in (t for t in trials if t is not None):
                fired = check in outcome
                if check in expected:
                    slot["tp" if fired else "fn"] += 1
                else:
                    slot["fp" if fired else "tn"] += 1

    for path, case in _HTTP_CASES.items():
        trials = [_http_checks(path) for _ in range(k)]
        cases[f"http {path}"] = {"case": case.name, **_score(trials, case.expected, http_universe)}
        _accumulate(case.expected, http_universe, trials)
    for port, case in _TLS_CASES.items():
        trials = [_tls_checks(port) for _ in range(k)]
        cases[f"tls :{port}"] = {
            "case": case.name,
            **_score(trials, case.expected, tls_universe),
            "unreadable_by_design": case.unreadable,
        }
        if any(t is not None for t in trials):
            _accumulate(case.expected, tls_universe, trials)
    groups: list[tuple[str, dict[str, Case], Callable[[str], set[CheckId] | None], set[CheckId]]] = [
        ("path", _PATH_CASES, _path_checks, {_DIR, _SENS, _LOGIN}),
        (
            "banner",
            _BANNER_CASES,
            _banner_checks,
            {CheckId.OUTDATED_EXPOSED_SOFTWARE, CheckId.EOL_SOFTWARE_EXPOSED},
        ),
        ("waf", _WAF_CASES, _waf_checks, {CheckId.WAF_ABSENT}),
        ("dns", _AXFR_CASES, _axfr_checks, {CheckId.DNS_ZONE_TRANSFER_OPEN}),
        ("dns", _DDOS_CASES, _ddos_checks, {CheckId.NO_DDOS_PROTECTION}),
        ("email", _EMAIL_CASES, _email_checks, set(_EMAIL)),
    ]
    for label, group, read, universe in groups:
        for target, case in group.items():
            trials = [read(target) for _ in range(k)]
            open_here = _NOT_READ.get(target, set()) if label in ("banner", "path") else set()
            cases[f"{label} {target}"] = {
                "case": case.name,
                **_score(trials, case.expected, universe),
                "unreadable_by_design": case.unreadable,
                "declared_false_positive": case.declared_false_positive,
                "detectors_left_unread": sorted(c.value for c in open_here),
            }
            if any(t is not None for t in trials) and case.declared_false_positive is None:
                _accumulate(case.expected, universe - open_here, trials)

    detectors: dict[str, Any] = {}
    for check, slot in sorted(per_detector.items(), key=lambda kv: kv[0].value):
        positives, negatives = slot["tp"] + slot["fn"], slot["fp"] + slot["tn"]
        entry: dict[str, Any] = {"positive_trials": positives, "negative_trials": negatives}
        if positives:
            ci = M.wilson_interval(slot["tp"], positives)
            entry["sensitivity"] = round(slot["tp"] / positives, 4)
            entry["sensitivity_ci"] = [round(ci.ci_low, 4), round(ci.ci_high, 4)]
        if negatives:
            ci = M.wilson_interval(slot["fp"], negatives)
            entry["false_alarm"] = round(slot["fp"] / negatives, 4)
            entry["false_alarm_ci"] = [round(ci.ci_low, 4), round(ci.ci_high, 4)]
        detectors[check.value] = entry
    return {
        "k": k,
        "cases": cases,
        "detectors": detectors,
        "note": "parsing correctness of the released inspectors against a one-axis-per-endpoint matrix. "
        "The Wilson intervals below are reported for completeness only: 60 identical requests to a "
        "static loopback endpoint are deterministic replicates, not Bernoulli trials, so they carry "
        "no sampling error and the paper reports agreement across configurations instead. "
        "Not a field measurement: the sensing model's acquisition factors cannot be reproduced on "
        "loopback and are not calibrated here.",
    }


def main() -> None:
    try:
        httpx.get(f"{HTTP_BASE}/", timeout=3.0)
    except httpx.HTTPError:
        message = f"matrix target not reachable at {HTTP_BASE}; start it with docker compose"
        raise SystemExit(message) from None
    result = measure()
    out = Path(__file__).resolve().parent / "detector_matrix_measured.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    summary = f"{len(result['detectors'])} detectors over {len(result['cases'])} cases"
    print(f"measured {summary} (k={result['k']}):")
    for cid, m in result["detectors"].items():
        sens = f"{m['sensitivity']:.3f} {m['sensitivity_ci']}" if "sensitivity" in m else "n/a"
        fa = f"{m['false_alarm']:.3f} {m['false_alarm_ci']}" if "false_alarm" in m else "n/a"
        print(f"  {cid:32s} sens={sens:22s} fa={fa}")
    for name, case in result["cases"].items():
        if case["unreadable"]:
            unread = f"{case['unreadable']} of {case['trials']}"
            print(f"  note: {name} ({case['case']}) unreadable in {unread} trials")


if __name__ == "__main__":
    main()
