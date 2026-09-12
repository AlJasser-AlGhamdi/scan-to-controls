from __future__ import annotations

from pathlib import Path

import pytest

from p2c.config import Settings
from p2c.scanning.signing import (
    DEV_TEMPLATE_SIGNING_KEY,
    TemplateSigner,
    sign_bytes,
    signer_from_settings,
    verify_bytes,
)

KEY = b"test-signing-key"


def _templates(tmp_path: Path) -> Path:
    (tmp_path / "a.yaml").write_text("id: a\n")
    (tmp_path / "b.yaml").write_text("id: b\n")
    return tmp_path


def test_sign_verify_roundtrip() -> None:
    assert verify_bytes(b"x", sign_bytes(b"x", KEY), KEY)
    assert not verify_bytes(b"x", sign_bytes(b"y", KEY), KEY)


def test_signed_templates_verify(tmp_path: Path) -> None:
    _templates(tmp_path)
    signer = TemplateSigner(KEY)
    signer.write_manifest(tmp_path)
    assert {p.name for p in signer.verified_templates(tmp_path)} == {"a.yaml", "b.yaml"}


def test_unsigned_template_rejected(tmp_path: Path) -> None:
    _templates(tmp_path)
    signer = TemplateSigner(KEY)
    signer.write_manifest(tmp_path)
    (tmp_path / "rogue.yaml").write_text("id: rogue\n")
    assert "rogue.yaml" not in {p.name for p in signer.verified_templates(tmp_path)}


def test_tampered_template_rejected(tmp_path: Path) -> None:
    _templates(tmp_path)
    signer = TemplateSigner(KEY)
    signer.write_manifest(tmp_path)
    (tmp_path / "a.yaml").write_text("id: a\nTAMPERED\n")
    verified = {p.name for p in signer.verified_templates(tmp_path)}
    assert "a.yaml" not in verified
    assert "b.yaml" in verified


def test_wrong_key_rejects_all(tmp_path: Path) -> None:
    _templates(tmp_path)
    TemplateSigner(KEY).write_manifest(tmp_path)
    assert TemplateSigner(b"different-key").verified_templates(tmp_path) == []


def test_empty_key_rejected() -> None:
    with pytest.raises(ValueError, match="signing key"):
        TemplateSigner(b"")


def test_signer_from_settings_refuses_dev_key_under_sovereign_mode() -> None:
    settings = Settings.model_validate(
        {"sovereign_mode": True, "template_signing_key": DEV_TEMPLATE_SIGNING_KEY}
    )
    with pytest.raises(ValueError, match="dev template-signing key"):
        signer_from_settings(settings)


def test_signer_from_settings_allows_real_key() -> None:
    settings = Settings.model_validate({"sovereign_mode": True, "template_signing_key": "a-real-secret-key"})
    assert signer_from_settings(settings) is not None


def test_signer_from_settings_dev_key_ok_with_escape_hatch() -> None:
    settings = Settings.model_validate(
        {
            "sovereign_mode": True,
            "template_signing_key": DEV_TEMPLATE_SIGNING_KEY,
            "allow_dev_template_key": True,
        }
    )
    assert signer_from_settings(settings) is not None
