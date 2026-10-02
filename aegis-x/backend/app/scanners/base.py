"""Scanner plugin contracts used by the modular scan pipeline."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from app.models.file_report import FileReport
from app.models.scanner_result import ScannerResult


@dataclass(frozen=True)
class ScannerContext:
    """Immutable input passed to each scanner."""

    file_path: Path
    report: FileReport


class BaseScanner(ABC):
    """Common interface every scanner plugin must implement."""

    scanner_name: str = "base"
    scanner_version: str = "unknown"
    description: str = ""
    default_enabled: bool = True
    scan_timeout_seconds: int = 30

    @abstractmethod
    def scan(self, context: ScannerContext) -> ScannerResult:
        """Inspect one file and return the scanner's own findings."""
        raise NotImplementedError

    def health_check(self) -> bool:
        """Return True if the scanner dependency is available and operational.

        Default implementation returns True (always healthy). Scanners with
        external dependencies (ClamAV, YARA) MUST override this.
        """
        return True
