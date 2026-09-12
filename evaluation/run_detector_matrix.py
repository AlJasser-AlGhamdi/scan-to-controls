from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from p2c.evaluation import metrics as M
from p2c.scanning.catalog import CheckId
from p2c.scanning.httpx_probe import HttpProbe, checks_for_probe
from p2c.scanning.tls import TlsInspector, evaluate_tls

HTTP_BASE = "http://127.0.0.1:9080"
TLS_HOST = "127.0.0.1"


@dataclass(frozen=True)
class Case:

    name: str
    expected: frozenset[CheckId]


_HTTP_CASES: dict[str, Case] = {
    "/": Case("no security headers", frozenset({
        CheckId.MISSING_HSTS, CheckId.MISSING_CSP, CheckId.MISSING_X_FRAME_OPTIONS,
        CheckId.MISSING_X_CONTENT_TYPE_OPTIONS, CheckId.MISSING_REFERRER_POLICY,
        CheckId.MISSING_PERMISSIONS_POLICY,
    })),
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
    9443: Case("self-signed RSA-2048", frozenset({CheckId.SELF_SIGNED_CERTIFICATE})),
    9444: Case("private-CA leaf, untrusted but not self-signed", frozenset()),
    9445: Case(
        "self-signed RSA-1024", frozenset({CheckId.SELF_SIGNED_CERTIFICATE, CheckId.WEAK_CERTIFICATE_KEY})
    ),
    9446: Case("self-signed RSA-4096", frozenset({CheckId.SELF_SIGNED_CERTIFICATE})),
    9447: Case("self-signed EC P-256", frozenset({CheckId.SELF_SIGNED_CERTIFICATE})),
    9448: Case(
        "self-signed EC secp192r1", frozenset({CheckId.SELF_SIGNED_CERTIFICATE, CheckId.WEAK_CERTIFICATE_KEY})
    ),
    9449: Case(
        "expired self-signed RSA-2048",
        frozenset({CheckId.EXPIRED_CERTIFICATE, CheckId.SELF_SIGNED_CERTIFICATE}),
    ),
}


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
        cases[f"tls :{port}"] = {"case": case.name, **_score(trials, case.expected, tls_universe)}
        if any(t is not None for t in trials):
            _accumulate(case.expected, tls_universe, trials)

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
