from __future__ import annotations

import http.server
import json
import socketserver
import threading
from pathlib import Path
from typing import Any

import httpx

from p2c.evaluation import metrics as M
from p2c.scanning.catalog import CheckId
from p2c.scanning.headers import analyze_security_headers

TARGET = "http://127.0.0.1:8081/"
HEADER_CHECKS: tuple[CheckId, ...] = (
    CheckId.MISSING_HSTS,
    CheckId.MISSING_CSP,
    CheckId.MISSING_X_FRAME_OPTIONS,
    CheckId.MISSING_X_CONTENT_TYPE_OPTIONS,
    CheckId.MISSING_REFERRER_POLICY,
)
_CLEAN_HEADERS = {
    "strict-transport-security": "max-age=63072000",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


class _CleanHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self) -> None:
        self.send_response(200)
        for name, value in _CLEAN_HEADERS.items():
            self.send_header(name, value)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"clean control\n")

    def log_message(self, *args: Any) -> None:
        return


def _serve_clean() -> tuple[socketserver.TCPServer, str]:
    server = socketserver.TCPServer(("127.0.0.1", 0), _CleanHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/"


def _detect(url: str) -> set[CheckId]:
    response = httpx.get(url, timeout=5.0)
    return set(analyze_security_headers(dict(response.headers)))


def calibrate_headers(k: int = 200) -> dict[str, Any]:
    sens = dict.fromkeys(HEADER_CHECKS, 0)
    for _ in range(k):
        detected = _detect(TARGET)
        for check in HEADER_CHECKS:
            sens[check] += int(check in detected)
    server, clean_url = _serve_clean()
    try:
        false_alarm = dict.fromkeys(HEADER_CHECKS, 0)
        for _ in range(k):
            detected = _detect(clean_url)
            for check in HEADER_CHECKS:
                false_alarm[check] += int(check in detected)
    finally:
        server.shutdown()
    checks: dict[str, Any] = {}
    for check in HEADER_CHECKS:
        s_ci = M.wilson_interval(sens[check], k)
        f_ci = M.wilson_interval(false_alarm[check], k)
        checks[check.value] = {
            "sensitivity": round(sens[check] / k, 4),
            "sensitivity_ci": [round(s_ci.ci_low, 4), round(s_ci.ci_high, 4)],
            "false_alarm": round(false_alarm[check] / k, 4),
            "false_alarm_ci": [round(f_ci.ci_low, 4), round(f_ci.ci_high, 4)],
        }
    return {
        "k": k,
        "target": TARGET,
        "checks": checks,
        "note": "measured on the reference implementation's own header inspector against the test-target "
        "(planted, all five security headers absent) and an in-process clean control (all present); "
        "sensitivity near 1.0 and false alarm near 0.0 confirm the deterministic-read model assumptions.",
    }


def main() -> None:
    try:
        httpx.get(TARGET, timeout=3.0)
    except httpx.HTTPError:
        raise SystemExit(f"test-target not reachable at {TARGET}; start it with docker compose") from None
    result = calibrate_headers()
    out = Path(__file__).resolve().parent / "calibration_measured.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"measured {len(result['checks'])} web-header checks live (k={result['k']}):")
    for cid, metrics in result["checks"].items():
        print(
            f"  {cid:32s} sensitivity={metrics['sensitivity']:.3f} {metrics['sensitivity_ci']}  "
            f"false_alarm={metrics['false_alarm']:.3f} {metrics['false_alarm_ci']}"
        )


if __name__ == "__main__":
    main()
