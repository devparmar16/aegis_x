"""
Centralized logging setup for Aegis-X.

All modules obtain loggers through `get_logger(__name__)`. Configuration
(level, file path) comes from AppConfig — never hardcoded here.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

_CONFIGURED = False


def _configure_root_logger(level: str, log_file_path: Path) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    log_file_path.parent.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger("aegis_x")
    root_logger.setLevel(getattr(logging, level, logging.INFO))
    root_logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    file_handler = RotatingFileHandler(
        filename=str(log_file_path),
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger under the `aegis_x` root logger.

    Lazily configures the root logger using AppConfig on first call,
    avoiding a hard import-time dependency on config for modules that
    only need a logger (e.g. during unit tests with mocked config).
    """
    try:
        from app.config.config import get_config

        config = get_config()
        _configure_root_logger(config.log_level, config.log_file_path)
    except Exception:
        # If config isn't available yet (e.g. very early startup or tests),
        # fall back to a sane default so logging never breaks the app.
        _configure_root_logger("INFO", Path("./logs/aegis_x.log"))

    return logging.getLogger(f"aegis_x.{name}")
