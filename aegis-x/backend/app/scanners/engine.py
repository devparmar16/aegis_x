"""Scanner engine that executes registered scanners independently."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Dict, Iterable, List, Sequence, Tuple

from app.config.config import AppConfig
from app.database.db_manager import DatabaseManager
from app.models.file_report import FileReport
from app.models.scanner_result import ScannerResult, ScannerStatus
from app.scanners.aggregator import EvidenceAggregator
from app.scanners.base import BaseScanner, ScannerContext
from app.utils.logger import get_logger

# We will import the real scanners. 
# Placeholder scanners can remain as fallback if real ones are disabled or fail.
from app.scanners.placeholder_scanners import (
    PEScanner,
    SignatureScanner,
    StaticAnalysisScanner,
)
from app.scanners.archive_scanner import ArchiveScanner
from app.scanners.filetype_scanner import FiletypeScanner
from app.scanners.yara_scanner import YaraScanner
from app.scanners.clamav_scanner import ClamAVScanner
from app.scanners.threat_intel_interface import create_threat_intel_provider

logger = get_logger(__name__)


@dataclass(frozen=True)
class ScannerExecution:
    """One scanner execution plus its result."""

    result: ScannerResult


class ScannerEngine:
    """Runs a registry of scanners and aggregates their findings."""

    def __init__(
        self,
        config: AppConfig,
        database: DatabaseManager,
        scanners: Optional[Sequence[BaseScanner]] = None,
    ) -> None:
        self._config = config
        self._db = database
        
        if scanners is None:
            # We must import ThreatIntelScanner here to avoid circular imports if needed, 
            # or just use it. Let's import it locally.
            from app.scanners.threat_intel_scanner import ThreatIntelScanner
            provider = create_threat_intel_provider(config)
            
            self._scanners = [
                StaticAnalysisScanner(),
                FiletypeScanner(),
                PEScanner(),
                SignatureScanner(),
                ArchiveScanner(),
                ThreatIntelScanner(provider),
                YaraScanner(config),
                ClamAVScanner(config),
            ]
        else:
            self._scanners = list(scanners)
            
        self._aggregator = EvidenceAggregator()
        self._ensure_scanner_settings()

    @property
    def scanners(self) -> Sequence[BaseScanner]:
        return tuple(self._scanners)

    def _ensure_scanner_settings(self) -> None:
        for scanner in self._scanners:
            key = self._setting_key(scanner.scanner_name)
            if self._db.get_setting(key) is None:
                self._db.set_setting(key, "true" if scanner.default_enabled else "false")

    @staticmethod
    def _setting_key(scanner_name: str) -> str:
        return f"scanner.enabled.{scanner_name}"

    def _is_enabled(self, scanner: BaseScanner) -> bool:
        raw = self._db.get_setting(self._setting_key(scanner.scanner_name), "true" if scanner.default_enabled else "false")
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}

    def _run_single_scanner(self, scanner: BaseScanner, context: ScannerContext) -> ScannerResult:
        """Execute a single scanner and wrap exceptions."""
        started_at = perf_counter()
        try:
            # Check health first
            if not scanner.health_check():
                result = ScannerResult(
                    scanner_name=scanner.scanner_name,
                    scanner_version=scanner.scanner_version,
                    status=ScannerStatus.UNAVAILABLE,
                    severity="Low",
                    evidence=[f"{scanner.scanner_name} is unavailable or missing dependencies."],
                )
            else:
                result = scanner.scan(context)
                
            result.enabled = True
            
        except Exception as exc:
            logger.error("Scanner %s failed: %s", scanner.scanner_name, exc, exc_info=True)
            result = ScannerResult(
                scanner_name=scanner.scanner_name,
                scanner_version=scanner.scanner_version,
                status=ScannerStatus.FAILURE,
                severity="High",
                evidence=[f"Scanner failed: {exc}"],
                raw_output={"error": str(exc)},
                errors=[str(exc)],
                enabled=True,
            )
            
        result.execution_time_ms = round((perf_counter() - started_at) * 1000, 2)
        return result

    def scan(self, report: FileReport) -> Tuple[List[ScannerResult], Dict[str, object]]:
        """Run all enabled scanners in parallel."""
        results: List[ScannerResult] = []
        context = ScannerContext(file_path=Path(report.metadata.absolute_path), report=report)
        
        active_scanners = []
        
        # Filter enabled scanners
        for scanner in self._scanners:
            if not self._is_enabled(scanner):
                results.append(
                    ScannerResult(
                        scanner_name=scanner.scanner_name,
                        status=ScannerStatus.DISABLED,
                        severity="Low",
                        evidence=[f"{scanner.scanner_name} disabled in settings"],
                        enabled=False,
                    )
                )
            else:
                active_scanners.append(scanner)

        # Run active scanners in parallel
        if active_scanners:
            with ThreadPoolExecutor(max_workers=len(active_scanners)) as executor:
                future_to_scanner = {
                    executor.submit(self._run_single_scanner, scanner, context): scanner
                    for scanner in active_scanners
                }
                
                for future in as_completed(future_to_scanner):
                    scanner = future_to_scanner[future]
                    # We apply the individual scanner timeout
                    timeout = getattr(scanner, "scan_timeout_seconds", self._config.scanner_timeout_seconds)
                    
                    try:
                        result = future.result(timeout=timeout)
                        results.append(result)
                    except FuturesTimeoutError:
                        logger.warning("Scanner %s timed out after %s seconds", scanner.scanner_name, timeout)
                        results.append(
                            ScannerResult(
                                scanner_name=scanner.scanner_name,
                                scanner_version=scanner.scanner_version,
                                status=ScannerStatus.FAILURE,
                                severity="High",
                                evidence=[f"Scanner timed out after {timeout} seconds"],
                                errors=["TimeoutError"],
                                enabled=True,
                            )
                        )
                    except Exception as exc:
                        logger.error("Scanner %s raised unhandled exception: %s", scanner.scanner_name, exc)
                        results.append(
                            ScannerResult(
                                scanner_name=scanner.scanner_name,
                                scanner_version=scanner.scanner_version,
                                status=ScannerStatus.FAILURE,
                                severity="High",
                                evidence=[f"Scanner raised unhandled exception: {exc}"],
                                errors=[str(exc)],
                                enabled=True,
                            )
                        )

        # Aggregate findings
        summary = self._aggregator.aggregate(report, results)
        return results, summary
