from __future__ import annotations

import os
import random
from functools import lru_cache
from typing import Annotated, Any

import numpy as np
from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from p2c.schemas.enums import RunMode


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ATLAS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    run_mode: RunMode = RunMode.SYNTHETIC
    sovereign_mode: bool = True
    global_seed: int = 1337

    allowlisted_hosts: Annotated[frozenset[str], NoDecode] = frozenset()
    allow_unguarded_loop: bool = False

    database_url: str = "postgresql+psycopg://atlas:atlas@127.0.0.1:5432/atlas"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    ollama_url: str = "http://127.0.0.1:11434"

    test_target_base_url: str | None = None

    template_signing_key: str = "atlas-dev-template-key-change-me"
    allow_dev_template_key: bool = False

    log_level: str = "INFO"
    log_json: bool = True

    @field_validator("allowlisted_hosts", mode="before")
    @classmethod
    def _parse_hosts(cls, value: Any) -> Any:
        if value is None or value == "":
            return frozenset()
        if isinstance(value, str):
            return frozenset(h.strip().lower() for h in value.split(",") if h.strip())
        if isinstance(value, (list, tuple, set, frozenset)):
            return frozenset(str(h).strip().lower() for h in value if str(h).strip())
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def seed_everything(seed: int | None = None) -> int:
    resolved = get_settings().global_seed if seed is None else seed
    os.environ["PYTHONHASHSEED"] = str(resolved)
    os.environ["ATLAS_SEED"] = str(resolved)
    random.seed(resolved)
    np.random.seed(resolved % (2**32))
    return resolved
