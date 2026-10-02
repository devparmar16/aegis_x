"""
Base interface for all evidence collectors.

Every collector takes a filesystem path and returns a piece of evidence.
Collectors are intentionally independent of each other so new ones
(e.g. a future "ScriptCollector" for .ps1/.js files) can be added without
touching existing code — this is the extensibility point called out in
the project requirements.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class BaseCollector(ABC):
    """Abstract base class for a single-responsibility evidence collector."""

    @abstractmethod
    def collect(self, file_path: Path) -> Any:
        """Collect and return evidence for the given file.

        Implementations must not raise on expected failure modes (locked
        file, permission denied, unsupported format) — they should log
        the issue and return a safe default instead, so one failing
        collector never aborts the whole analysis pipeline.
        """
        raise NotImplementedError
