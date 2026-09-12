from __future__ import annotations

from p2c.sovereignty.provenance import canonical_json, content_hash, sha256_hex


def test_sha256_hex_known_empty() -> None:
    assert sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_canonical_json_is_stable_and_sorted() -> None:
    assert canonical_json({"y": [3, 2, 1], "x": 1}) == '{"x":1,"y":[3,2,1]}'


def test_content_hash_is_key_order_independent() -> None:
    left = content_hash({"a": 2, "b": 1})
    right = content_hash({"b": 1, "a": 2})
    assert left == right
    assert len(left) == 64


def test_content_hash_changes_with_content() -> None:
    assert content_hash({"a": 1}) != content_hash({"a": 2})
