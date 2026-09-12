from __future__ import annotations

import ipaddress
import re

import idna

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")

_ASCII_SPACE = 0x20
_ASCII_DEL = 0x7F


def _is_ascii_control(ch: str) -> bool:
    return ch.isascii() and (ord(ch) < _ASCII_SPACE or ord(ch) == _ASCII_DEL)


def _clean(value: str) -> str:
    host = value.strip().lower()
    if any(ch.isspace() or _is_ascii_control(ch) for ch in host):
        return ""
    host = host.rstrip(".")
    while host.startswith("*."):
        host = host[2:]
    return host


def to_ascii(host: str) -> str:
    if host.isascii():
        return host
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        return ""


def to_unicode(host: str) -> str:
    try:
        return idna.decode(host)
    except (idna.IDNAError, UnicodeError):
        return host


def canonical_host(value: str) -> str:
    return to_ascii(_clean(value))


normalize_host = canonical_host


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def is_valid_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.match(canonical_host(value)))


def require_hostname(target: str) -> str:
    normalized = canonical_host(target)
    if not is_valid_hostname(normalized):
        raise ValueError(f"invalid target hostname: {target!r}")
    return normalized


def in_scope_of(host: str, apex: str) -> bool:
    if is_ip(host):
        return True
    normalized, apex_norm = canonical_host(host), canonical_host(apex)
    return bool(normalized) and (normalized == apex_norm or normalized.endswith(f".{apex_norm}"))


def candidate_apexes(host: str) -> list[str]:
    normalized = canonical_host(host)
    if not normalized:
        return []
    if is_ip(normalized):
        return [normalized]
    labels = normalized.split(".")
    return [".".join(labels[i:]) for i in range(len(labels))]
