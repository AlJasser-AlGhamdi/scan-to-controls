from __future__ import annotations

from collections.abc import Iterator

import pytest

from p2c.config import Settings, get_settings
from p2c.sovereignty import egress_guard


@pytest.fixture(autouse=True)
def _reset_p2c_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    get_settings.cache_clear()
    yield
    egress_guard.uninstall()
    get_settings.cache_clear()
