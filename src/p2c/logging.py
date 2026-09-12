from __future__ import annotations

import logging

import structlog

from p2c.config import Settings, get_settings


def configure_logging(settings: Settings | None = None) -> None:
    cfg = settings or get_settings()
    level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", level=level)

    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer() if cfg.log_json else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
