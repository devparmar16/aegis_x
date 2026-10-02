"""
Threat intelligence scanner.
Looks up file hashes (SHA-256) in configured Threat Intelligence providers
(e.g., VirusTotal, MalwareBazaar) to determine known malicious status.
"""

from __future__ import annotations

from app.models.scanner_result import ScannerResult, ScannerStatus
from app.scanners.base import BaseScanner, ScannerContext
from app.scanners.threat_intel_interface import ThreatIntelProvider
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatIntelScanner(BaseScanner):
    """Queries external intelligence sources using file hashes."""

    scanner_name = "threat_intel"
    description = "External threat intelligence (e.g. VirusTotal)"
    default_enabled = True

    def __init__(self, provider: ThreatIntelProvider) -> None:
        self._provider = provider

    def health_check(self) -> bool:
        """Returns True if threat intel is enabled in the config."""
        return self._provider.config.threat_intel_enabled

    def scan(self, context: ScannerContext) -> ScannerResult:
        if not self._provider.config.threat_intel_enabled:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.DISABLED,
                severity="Low",
                confidence=0.0,
                evidence=["Threat intelligence is disabled in configuration"],
            )

        sha256 = context.report.hashes.sha256
        if not sha256:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.WARNING,
                severity="Low",
                confidence=0.0,
                evidence=["No SHA-256 hash available for lookup"],
            )

        try:
            result = self._provider.hash_lookup(sha256)
            
            if result.status == "unavailable":
                return ScannerResult(
                    scanner_name=self.scanner_name,
                    status=ScannerStatus.UNAVAILABLE,
                    severity="Low",
                    confidence=0.0,
                    evidence=[result.error or "Provider unavailable"],
                )
            
            if result.status == "error":
                return ScannerResult(
                    scanner_name=self.scanner_name,
                    status=ScannerStatus.FAILURE,
                    severity="High",
                    confidence=0.0,
                    evidence=["Threat Intel lookup failed"],
                    errors=[result.error or "Unknown error"],
                )

            if not result.found:
                return ScannerResult(
                    scanner_name=self.scanner_name,
                    status=ScannerStatus.SUCCESS,
                    severity="Low",
                    confidence=0.8,
                    evidence=["File hash not found in threat intelligence databases"],
                    raw_output=result.raw_response,
                    detection_count=0,
                )

            # File was found
            context.report.threat_intel = result

            if result.malicious:
                return ScannerResult(
                    scanner_name=self.scanner_name,
                    status=ScannerStatus.SUCCESS,
                    severity="Critical",
                    confidence=1.0,
                    findings=["KNOWN_MALICIOUS"],
                    evidence=[f"Flagged as malicious by {self._provider.provider_name}"],
                    raw_output=result.raw_response,
                    detection_count=1,
                )
            else:
                return ScannerResult(
                    scanner_name=self.scanner_name,
                    status=ScannerStatus.SUCCESS,
                    severity="Low",
                    confidence=0.9,
                    evidence=[f"Known safe/clean according to {self._provider.provider_name}"],
                    raw_output=result.raw_response,
                    detection_count=0,
                )
                
        except Exception as exc:
            logger.error("ThreatIntelScanner encountered unexpected error: %s", exc)
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.FAILURE,
                severity="High",
                confidence=0.0,
                evidence=["Unexpected error during threat intel lookup"],
                errors=[str(exc)],
            )
