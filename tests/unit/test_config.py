from __future__ import annotations

import os
import random

import numpy as np
import pytest

from p2c.config import Settings, get_settings, seed_everything


def _clear_atlas_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("ATLAS_"):
            monkeypatch.delenv(key, raising=False)


def test_defaults_are_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_atlas_env(monkeypatch)
    settings = Settings()
    assert settings.run_mode.value == "SYNTHETIC"
    assert settings.sovereign_mode is True
    assert settings.global_seed == 1337
    assert settings.allowlisted_hosts == frozenset()


def test_allowlist_parsed_from_comma_string() -> None:
    settings = Settings.model_validate({"allowlisted_hosts": "crt.sh, Example.COM ,"})
    assert settings.allowlisted_hosts == frozenset({"crt.sh", "example.com"})


def test_allowlist_parsed_from_iterable() -> None:
    settings = Settings.model_validate({"allowlisted_hosts": ["A.com", "b.com", "b.com"]})
    assert settings.allowlisted_hosts == frozenset({"a.com", "b.com"})


def test_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATLAS_RUN_MODE", "LIVE")
    monkeypatch.setenv("ATLAS_SOVEREIGN_MODE", "false")
    monkeypatch.setenv("ATLAS_GLOBAL_SEED", "42")
    monkeypatch.setenv("ATLAS_ALLOWLISTED_HOSTS", "a.com,b.com")
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.run_mode.value == "LIVE"
    assert settings.sovereign_mode is False
    assert settings.global_seed == 42
    assert settings.allowlisted_hosts == frozenset({"a.com", "b.com"})


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()


def test_seed_everything_is_deterministic() -> None:
    seed_everything(123)
    py_a = [random.random() for _ in range(5)]
    np_a = np.random.rand(5).tolist()

    seed_everything(123)
    py_b = [random.random() for _ in range(5)]
    np_b = np.random.rand(5).tolist()

    assert py_a == py_b
    assert np_a == np_b
    assert os.environ["PYTHONHASHSEED"] == "123"
    assert os.environ["ATLAS_SEED"] == "123"


def test_seed_everything_uses_settings_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_atlas_env(monkeypatch)
    get_settings.cache_clear()
    assert seed_everything() == 1337
