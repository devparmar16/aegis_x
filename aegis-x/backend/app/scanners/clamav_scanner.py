"""
ClamAV socket scanner for connecting to a local or remote clamd daemon.
"""

from __future__ import annotations

import clamd
from typing import Optional

from app.config.config import AppConfig
from app.models.scanner_result import ScannerResult, ScannerStatus
from app.scanners.base import BaseScanner, ScannerContext
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ClamAVScanner(BaseScanner):
    """Submits files to a clamd TCP socket for signature matching."""

    scanner_name = "clamav"
    description = "ClamAV daemon integration"
    default_enabled = True

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self._clamd: Optional[clamd.ClamdNetworkSocket] = None
        
        if self.config.clamav_enabled:
            self._clamd = clamd.ClamdNetworkSocket(
                host=self.config.clamd_host, 
                port=self.config.clamd_port, 
                timeout=self.config.scanner_timeout_seconds
            )

    def health_check(self) -> bool:
        """Returns True if ClamAV is enabled and reachable."""
        if not self.config.clamav_enabled or not self._clamd:
            return False
            
        try:
            pong = self._clamd.ping()
            return pong == 'PONG'
        except Exception:
            return False

    def scan(self, context: ScannerContext) -> ScannerResult:
        if not self.config.clamav_enabled:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.DISABLED,
                severity="Low",
                confidence=0.0,
                evidence=["ClamAV scanning is disabled in configuration"],
            )

        if not self._clamd:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.UNAVAILABLE,
                severity="Low",
                confidence=0.0,
                evidence=["ClamAV socket is not configured properly"],
            )

        try:
            # clamd.instream expects a file-like object
            with open(context.file_path, "rb") as f:
                # Returns dict like {'stream': ('FOUND', 'Win.Test.EICAR_HDB-1')}
                result = self._clamd.instream(f)
                
            stream_result = result.get("stream", ("ERROR", "Unknown response"))
            status = stream_result[0]
            
            if status == "OK":
                return ScannerResult(
                    scanner_name=self.scanner_name,
                    status=ScannerStatus.SUCCESS,
                    severity="Low",
                    confidence=0.9,
                    evidence=["No threats detected by ClamAV"],
                    detection_count=0,
                )
            elif status == "FOUND":
                threat_name = stream_result[1]
                return ScannerResult(
                    scanner_name=self.scanner_name,
                    status=ScannerStatus.SUCCESS,
                    severity="Critical",  # AV detections are typically Critical
                    confidence=1.0,
                    findings=[f"CLAMAV_{threat_name}"],
                    evidence=[f"ClamAV detected threat: {threat_name}"],
                    raw_output=result,
                    detection_count=1,
                )
            else:
                return ScannerResult(
                    scanner_name=self.scanner_name,
                    status=ScannerStatus.FAILURE,
                    severity="High",
                    confidence=0.0,
                    evidence=[f"ClamAV returned unexpected status: {status}"],
                    raw_output=result,
                    errors=[str(stream_result)],
                )

        except clamd.BufferTooLongError:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.FAILURE,
                severity="High",
                confidence=0.0,
                evidence=["File exceeds ClamAV max size limits"],
                errors=["BufferTooLongError"],
            )
        except clamd.ConnectionError as exc:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.UNAVAILABLE,
                severity="High",
                confidence=0.0,
                evidence=["Failed to connect to clamd"],
                errors=[str(exc)],
            )
        except Exception as exc:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.FAILURE,
                severity="High",
                confidence=0.0,
                evidence=["Unexpected error during ClamAV scan"],
                errors=[str(exc)],
            )
