from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from p2c._embed import normalize_text


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: str | bytes) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def content_hash(payload: Any) -> str:
    return sha256_hex(canonical_json(payload))


_NOT_KEPT = re.compile(r"[^\u0621-\u064a\u0660-\u06690-9]+")


def canonical_arabic(text: str) -> str:
    return " ".join(part for part in _NOT_KEPT.split(normalize_text(text)) if part)


def text_fingerprint(text: str) -> str:
    return sha256_hex(canonical_arabic(text))
