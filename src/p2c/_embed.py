from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from typing import Protocol, runtime_checkable

_TOKEN_RE = re.compile(r"\w+", re.UNICODE)
DEFAULT_DIM = 256
_NGRAM = 3

_ARABIC_DIACRITICS = re.compile(r"[ؐ-ًؚ-ٰٟۖ-ۭـ]")
_ARABIC_NORM_MAP = str.maketrans(
    {
        "أ": "ا",
        "إ": "ا",
        "آ": "ا",
        "ٱ": "ا",
        "ى": "ي",
        "ة": "ه",
    }
)


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFC", text).lower()
    text = _ARABIC_DIACRITICS.sub("", text)
    return text.translate(_ARABIC_NORM_MAP)


@runtime_checkable
class Embedder(Protocol):

    dimension: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


def _char_ngrams(token: str, n: int) -> list[str]:
    padded = f"^{token}$"
    if len(padded) <= n:
        return [padded]
    return [padded[i : i + n] for i in range(len(padded) - n + 1)]


class HashingEmbedder:
    def __init__(self, dimension: int = DEFAULT_DIM, *, ngram: int = _NGRAM) -> None:
        self.dimension = dimension
        self._ngram = ngram
        self.name = "hashing"

    def _bucket(self, gram: str) -> int:
        digest = hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest()
        return int.from_bytes(digest, "big") % self.dimension

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_one(t) for t in texts]

    def _embed_one(self, text: str) -> list[float]:
        vector = [0.0] * self.dimension
        for token in _TOKEN_RE.findall(normalize_text(text)):
            for gram in _char_ngrams(token, self._ngram):
                vector[self._bucket(gram)] += 1.0
        norm = math.sqrt(sum(v * v for v in vector))
        if norm == 0.0:
            return vector
        return [v / norm for v in vector]


def cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        raise ValueError("vectors must have equal length")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)
