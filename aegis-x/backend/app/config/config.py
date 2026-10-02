"""
Central configuration module for Aegis-X.

This is the ONLY module in the codebase allowed to read environment
variables directly. Every other module receives configuration through
the `AppConfig` object (typically via dependency injection), so paths,
keys, and tunables are never hardcoded elsewhere.

Usage:
    from app.config.config import get_config
    config = get_config()
    print(config.scan_folders)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv


class ConfigurationError(Exception):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class AppConfig:
    """Immutable, typed representation of the application's configuration."""

    # -----------------------------------------------------------------------
    # Scanning folders (the user's watched / scan targets)
    # -----------------------------------------------------------------------
    scan_folders: List[Path]
    file_stabilize_delay_seconds: float
    ignored_extensions: List[str]
    scan_recursive: bool

    # -----------------------------------------------------------------------
    # AI Provider
    # -----------------------------------------------------------------------
    ai_provider: str
    groq_api_key: Optional[str]
    gemini_api_key: Optional[str]
    openai_api_key: Optional[str]
    model_name: str
    ollama_base_url: str
    ai_request_timeout_seconds: int

    # -----------------------------------------------------------------------
    # Database
    # -----------------------------------------------------------------------
    database_path: Path

    # -----------------------------------------------------------------------
    # Logging
    # -----------------------------------------------------------------------
    log_level: str
    log_file_path: Path

    # -----------------------------------------------------------------------
    # UI
    # -----------------------------------------------------------------------
    auto_open_popup: bool

    # -----------------------------------------------------------------------
    # Web API / Dashboard
    # -----------------------------------------------------------------------
    api_host: str
    api_port: int

    # -----------------------------------------------------------------------
    # ClamAV (clamd socket mode)
    # -----------------------------------------------------------------------
    clamd_host: str
    clamd_port: int
    clamav_enabled: bool

    # -----------------------------------------------------------------------
    # YARA
    # -----------------------------------------------------------------------
    yara_rules_dir: Optional[Path]
    yara_enabled: bool

    # -----------------------------------------------------------------------
    # Scanner timeouts
    # -----------------------------------------------------------------------
    scanner_timeout_seconds: int
    scan_timeout_seconds: int

    # -----------------------------------------------------------------------
    # Threat Intelligence
    # -----------------------------------------------------------------------
    virustotal_api_key: Optional[str]
    malwarebazaar_api_key: Optional[str]
    threat_intel_enabled: bool

    # -----------------------------------------------------------------------
    # System Enumeration
    # -----------------------------------------------------------------------
    system_scan_interval_seconds: int

    def validate(self) -> None:
        """Validate configuration values, raising ConfigurationError on problems."""
        valid_providers = {"groq", "gemini", "openai", "ollama", "none"}
        if self.ai_provider not in valid_providers:
            raise ConfigurationError(
                f"AI_PROVIDER must be one of {sorted(valid_providers)}, "
                f"got '{self.ai_provider}'"
            )

        if self.file_stabilize_delay_seconds < 0:
            raise ConfigurationError(
                "FILE_STABILIZE_DELAY_SECONDS must be >= 0"
            )

        if self.ai_request_timeout_seconds <= 0:
            raise ConfigurationError(
                "AI_REQUEST_TIMEOUT_SECONDS must be > 0"
            )

        if not (1 <= self.api_port <= 65535):
            raise ConfigurationError(
                f"API_PORT must be between 1 and 65535, got {self.api_port}"
            )

        if self.scanner_timeout_seconds <= 0:
            raise ConfigurationError("SCANNER_TIMEOUT_SECONDS must be > 0")

        if self.system_scan_interval_seconds < 10:
            raise ConfigurationError("SYSTEM_SCAN_INTERVAL_SECONDS must be >= 10")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _split_csv(raw: str) -> List[str]:
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def _split_paths(raw: str) -> List[str]:
    """Split a comma- or newline-separated list of paths."""
    paths = []
    for item in raw.replace("\n", ",").split(","):
        item = item.strip()
        if item:
            paths.append(item)
    return paths


def _str_to_bool(raw: str) -> bool:
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _load_env_file() -> None:
    """Load a `.env` file from the backend root."""
    backend_root = Path(__file__).resolve().parents[2]
    env_path = backend_root / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)
    else:
        load_dotenv(override=False)


def _default_scan_folder() -> str:
    """Return the user's Downloads folder as the default scan target."""
    userprofile = os.environ.get("USERPROFILE", os.path.expanduser("~"))
    return str(Path(userprofile) / "Downloads")


def _build_config() -> AppConfig:
    _load_env_file()

    # Scan folders — SCAN_FOLDERS is primary; CHROME_DOWNLOAD_PATH is
    # a legacy fallback so existing .env files keep working.
    scan_folders_raw = (
        os.getenv("SCAN_FOLDERS", "").strip()
        or os.getenv("CHROME_DOWNLOAD_PATH", "").strip()
        or _default_scan_folder()
    )
    scan_folder_strs = _split_paths(scan_folders_raw)
    scan_folders = [Path(p) for p in scan_folder_strs] if scan_folder_strs else [Path(_default_scan_folder())]

    database_path_raw = os.getenv("DATABASE_PATH", "./data/aegis_x.db").strip()
    log_file_path_raw = os.getenv("LOG_FILE_PATH", "./logs/aegis_x.log").strip()

    yara_dir_raw = os.getenv("YARA_RULES_DIR", "").strip()
    yara_rules_dir = Path(yara_dir_raw) if yara_dir_raw else None

    config = AppConfig(
        # Scanning
        scan_folders=scan_folders,
        file_stabilize_delay_seconds=float(os.getenv("FILE_STABILIZE_DELAY_SECONDS", "2")),
        ignored_extensions=_split_csv(os.getenv("IGNORED_EXTENSIONS", "crdownload,tmp,part,download")),
        scan_recursive=_str_to_bool(os.getenv("SCAN_RECURSIVE", "false")),

        # AI
        ai_provider=os.getenv("AI_PROVIDER", "none").strip().lower(),
        groq_api_key=os.getenv("GROQ_API_KEY") or None,
        gemini_api_key=os.getenv("GEMINI_API_KEY") or None,
        openai_api_key=os.getenv("OPENAI_API_KEY") or None,
        model_name=os.getenv("MODEL_NAME", "").strip(),
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").strip(),
        ai_request_timeout_seconds=int(os.getenv("AI_REQUEST_TIMEOUT_SECONDS", "20")),

        # Database
        database_path=Path(database_path_raw),

        # Logging
        log_level=os.getenv("LOG_LEVEL", "INFO").strip().upper(),
        log_file_path=Path(log_file_path_raw),

        # UI
        auto_open_popup=_str_to_bool(os.getenv("AUTO_OPEN_POPUP", "true")),

        # API
        api_host=os.getenv("API_HOST", "127.0.0.1").strip(),
        api_port=int(os.getenv("API_PORT", "8000")),

        # ClamAV
        clamd_host=os.getenv("CLAMD_HOST", "127.0.0.1").strip(),
        clamd_port=int(os.getenv("CLAMD_PORT", "3310")),
        clamav_enabled=_str_to_bool(os.getenv("CLAMAV_ENABLED", "true")),

        # YARA
        yara_rules_dir=yara_rules_dir,
        yara_enabled=_str_to_bool(os.getenv("YARA_ENABLED", "true")),

        # Timeouts
        scanner_timeout_seconds=int(os.getenv("SCANNER_TIMEOUT_SECONDS", "30")),
        scan_timeout_seconds=int(os.getenv("SCAN_TIMEOUT_SECONDS", "120")),

        # Threat Intel
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
        malwarebazaar_api_key=os.getenv("MALWAREBAZAAR_API_KEY") or None,
        threat_intel_enabled=_str_to_bool(os.getenv("THREAT_INTEL_ENABLED", "false")),

        # System
        system_scan_interval_seconds=int(os.getenv("SYSTEM_SCAN_INTERVAL_SECONDS", "60")),
    )
    config.validate()
    return config


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """Return the process-wide singleton AppConfig, building it on first call."""
    return _build_config()
