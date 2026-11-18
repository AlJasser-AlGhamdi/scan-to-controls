from __future__ import annotations

import re

from p2c.scanning.catalog import CheckId

_SECURITY_HEADERS: dict[str, CheckId] = {
    "strict-transport-security": CheckId.MISSING_HSTS,
    "content-security-policy": CheckId.MISSING_CSP,
    "x-frame-options": CheckId.MISSING_X_FRAME_OPTIONS,
    "x-content-type-options": CheckId.MISSING_X_CONTENT_TYPE_OPTIONS,
    "referrer-policy": CheckId.MISSING_REFERRER_POLICY,
    "permissions-policy": CheckId.MISSING_PERMISSIONS_POLICY,
}


def analyze_security_headers(headers: dict[str, str]) -> list[CheckId]:
    values = {name.lower(): value for name, value in headers.items() if value.strip()}
    present = set(values)
    if "frame-ancestors" in values.get("content-security-policy", "").lower():
        present.add("x-frame-options")
    hsts = _MAX_AGE.search(values.get("strict-transport-security", ""))
    if "strict-transport-security" in present and not (hsts and int(hsts.group(1)) > 0):
        present.discard("strict-transport-security")
    return [check for header, check in _SECURITY_HEADERS.items() if header not in present]


_MAX_AGE = re.compile(r"(?i)max-age\s*=\s*\"?(\d{1,12})")
