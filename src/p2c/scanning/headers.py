from __future__ import annotations

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
    present = {name.lower() for name in headers}
    return [check for header, check in _SECURITY_HEADERS.items() if header not in present]
