from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from p2c.config import Settings

MANIFEST_NAME = "_signatures.json"
DEV_TEMPLATE_SIGNING_KEY = "atlas-dev-template-key-change-me"


def sign_bytes(content: bytes, key: bytes) -> str:
    return hmac.new(key, content, hashlib.sha256).hexdigest()


def verify_bytes(content: bytes, signature: str, key: bytes) -> bool:
    return hmac.compare_digest(sign_bytes(content, key), signature)


def signer_from_settings(settings: Settings) -> TemplateSigner:
    key = settings.template_signing_key
    if settings.sovereign_mode and key == DEV_TEMPLATE_SIGNING_KEY and not settings.allow_dev_template_key:
        raise ValueError(
            "refusing the built-in dev template-signing key under SOVEREIGN_MODE; "
            "set ATLAS_TEMPLATE_SIGNING_KEY to a real secret and re-run `make sign-templates`"
        )
    return TemplateSigner(key.encode())


class TemplateSigner:

    def __init__(self, key: bytes) -> None:
        if not key:
            raise ValueError("template signing key must not be empty")
        self._key = key

    def sign_dir(self, template_dir: Path) -> dict[str, str]:
        return {p.name: sign_bytes(p.read_bytes(), self._key) for p in sorted(template_dir.glob("*.yaml"))}

    def write_manifest(self, template_dir: Path) -> Path:
        manifest = self.sign_dir(template_dir)
        path = template_dir / MANIFEST_NAME
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def load_manifest(self, template_dir: Path) -> dict[str, str]:
        path = template_dir / MANIFEST_NAME
        if not path.exists():
            return {}
        loaded = json.loads(path.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in loaded.items()}

    def verified_templates(self, template_dir: Path, manifest: dict[str, str] | None = None) -> list[Path]:
        sigs = manifest if manifest is not None else self.load_manifest(template_dir)
        verified: list[Path] = []
        for path in sorted(template_dir.glob("*.yaml")):
            signature = sigs.get(path.name)
            if signature and verify_bytes(path.read_bytes(), signature, self._key):
                verified.append(path)
        return verified
