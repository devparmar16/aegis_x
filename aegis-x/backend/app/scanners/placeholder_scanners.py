"""Built-in scanner implementations that provide the modular framework.

These scanners deliberately avoid custom malware detection. They only
surface structural evidence and integration placeholders so future tools
can be plugged in without changing orchestration code.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from typing import List

from app.collectors.file_info_collector import _EXECUTABLE_EXTENSIONS
from app.models.file_report import FileReport, Severity
from app.models.scanner_result import ScannerResult, ScannerStatus
from app.scanners.base import BaseScanner, ScannerContext


def _highest_severity(values: List[str]) -> str:
    if Severity.CRITICAL.value in values:
        return Severity.CRITICAL.value
    if Severity.HIGH.value in values:
        return Severity.HIGH.value
    if Severity.MEDIUM.value in values:
        return Severity.MEDIUM.value
    return Severity.LOW.value


class StaticAnalysisScanner(BaseScanner):
    """Produces structural findings from filename, extension, and metadata."""

    scanner_name = "static_analysis"
    description = "Structural file analysis without malware verdicts"
    default_enabled = True

    def scan(self, context: ScannerContext) -> ScannerResult:
        metadata = context.report.metadata
        evidence: List[str] = [
            f"Extension: .{metadata.extension or 'unknown'}",
            f"MIME type: {metadata.mime_type}",
            f"Entropy: {metadata.entropy:.2f} / 8.0",
            f"Size: {metadata.size_bytes:,} bytes",
        ]
        severity = Severity.LOW.value
        confidence = 0.4
        detection_count = 0

        if metadata.is_executable:
            severity = Severity.MEDIUM.value
            confidence = 0.8
            detection_count += 1
            evidence.append("File is executable-capable")

        if metadata.extension in {"ps1", "bat", "cmd", "vbs", "js", "hta"}:
            severity = Severity.HIGH.value
            confidence = 0.9
            detection_count += 1
            evidence.append("Script or launcher extension present")

        if metadata.extension in _EXECUTABLE_EXTENSIONS and metadata.absolute_path.lower().endswith(f".{metadata.extension}.{metadata.extension}"):
            severity = Severity.HIGH.value
            confidence = 0.95
            detection_count += 1
            evidence.append("Double extension pattern detected")

        return ScannerResult(
            scanner_name=self.scanner_name,
            status=ScannerStatus.SUCCESS,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            raw_output={"filename": metadata.filename, "path": metadata.absolute_path},
            detection_count=detection_count,
        )


class PEScanner(BaseScanner):
    """Reports Windows PE security posture when a PE header is available."""

    scanner_name = "pe"
    description = "PE header inspection"
    default_enabled = True

    def scan(self, context: ScannerContext) -> ScannerResult:
        pe = context.report.pe_info
        if pe is None:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.SKIPPED,
                severity=Severity.LOW.value,
                confidence=0.0,
                evidence=["Not a PE file"],
                raw_output={"reason": "PE info unavailable"},
            )

        evidence = [
            f"Architecture: {pe.architecture or 'unknown'}",
            f"Type: {pe.executable_type or 'unknown'}",
            f"ASLR: {'enabled' if pe.aslr_enabled else 'disabled'}",
            f"DEP/NX: {'enabled' if pe.dep_nx_enabled else 'disabled'}",
            f"CFG: {'enabled' if pe.cfg_enabled else 'disabled'}",
        ]
        flags: List[str] = []
        if not pe.aslr_enabled:
            flags.append(Severity.HIGH.value)
            evidence.append("ASLR is disabled")
        if not pe.dep_nx_enabled:
            flags.append(Severity.HIGH.value)
            evidence.append("DEP/NX is disabled")
        if not pe.cfg_enabled:
            flags.append(Severity.MEDIUM.value)
            evidence.append("CFG is disabled")
        if pe.suspicious_sections:
            flags.append(Severity.HIGH.value)
            evidence.append(f"Suspicious sections: {', '.join(pe.suspicious_sections)}")
        if pe.suspicious_imports:
            flags.append(Severity.HIGH.value)
            evidence.append(f"Suspicious imports: {', '.join(pe.suspicious_imports)}")

        severity = _highest_severity(flags)
        confidence = 0.9 if pe.section_names else 0.75
        return ScannerResult(
            scanner_name=self.scanner_name,
            status=ScannerStatus.SUCCESS,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            raw_output=pe.model_dump(mode="json"),
            detection_count=len(flags),
        )


class SignatureScanner(BaseScanner):
    """Reports signature and publisher status."""

    scanner_name = "signature"
    description = "Digital signature inspection"
    default_enabled = True

    def scan(self, context: ScannerContext) -> ScannerResult:
        signature = context.report.signature
        
        if signature.status.value == "not_applicable":
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.SKIPPED,
                severity=Severity.LOW.value,
                confidence=0.0,
                evidence=["Not a PE executable, signature check not applicable"],
                raw_output={"reason": "not applicable"}
            )
            
        evidence = [f"Status: {signature.status.value}", f"Publisher: {signature.publisher or 'unknown'}"]
        severity = Severity.LOW.value
        confidence = 0.85
        detection_count = 0

        if signature.status.value == "signed_invalid":
            severity = Severity.HIGH.value
            detection_count = 1
            evidence.append("Signature verification failed")
        elif signature.status.value == "unsigned":
            severity = Severity.MEDIUM.value if context.report.metadata.is_executable else Severity.LOW.value
            detection_count = 1 if context.report.metadata.is_executable else 0
            evidence.append("File is unsigned")
        elif signature.status.value == "unknown":
            severity = Severity.LOW.value
            evidence.append("Signature status unknown")

        return ScannerResult(
            scanner_name=self.scanner_name,
            status=ScannerStatus.SUCCESS,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            raw_output=signature.model_dump(mode="json"),
            detection_count=detection_count,
        )


class ArchiveScanner(BaseScanner):
    """Inspects archive containers without unpacking nested payloads."""

    scanner_name = "archive"
    description = "Archive/container inspection"
    default_enabled = True

    def scan(self, context: ScannerContext) -> ScannerResult:
        path = context.file_path
        metadata = context.report.metadata
        archive_exts = {"zip", "jar", "msi", "rar", "7z", "tar", "gz", "bz2", "xz"}
        if metadata.extension not in archive_exts and not zipfile.is_zipfile(path):
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.SKIPPED,
                severity=Severity.LOW.value,
                confidence=0.0,
                evidence=["Not an archive file"],
                raw_output={"reason": "archive check not applicable"},
            )

        entries: List[str] = []
        nested_count = 0
        try:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as archive:
                    names = archive.namelist()
                    entries = names[:20]
                    for name in names:
                        if Path(name).suffix.lower().lstrip(".") in archive_exts:
                            nested_count += 1
        except Exception as exc:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.WARNING,
                severity=Severity.LOW.value,
                confidence=0.3,
                evidence=["Archive could not be enumerated"],
                raw_output={"error": str(exc)},
                errors=[str(exc)],
            )

        severity = Severity.MEDIUM.value if nested_count else Severity.LOW.value
        evidence = [f"Archive entries: {len(entries)} shown"]
        if nested_count:
            evidence.append(f"Nested archive-like entries: {nested_count}")
        return ScannerResult(
            scanner_name=self.scanner_name,
            status=ScannerStatus.SUCCESS,
            severity=severity,
            confidence=0.7,
            evidence=evidence,
            raw_output={"entries": entries, "nested_archive_entries": nested_count},
            detection_count=nested_count,
        )


class ThreatIntelScanner(BaseScanner):
    """Placeholder threat-intelligence integration."""

    scanner_name = "threat_intel"
    description = "Threat intelligence integration placeholder"
    default_enabled = False

    def scan(self, context: ScannerContext) -> ScannerResult:
        return ScannerResult(
            scanner_name=self.scanner_name,
            status=ScannerStatus.DISABLED,
            severity=Severity.LOW.value,
            confidence=0.0,
            evidence=["Threat intelligence integration is not enabled in this build"],
            raw_output={"placeholder": True},
        )


class YaraScanner(BaseScanner):
    """Placeholder YARA integration that can be enabled later without code changes."""

    scanner_name = "yara"
    description = "YARA integration placeholder"
    default_enabled = False

    def scan(self, context: ScannerContext) -> ScannerResult:
        return ScannerResult(
            scanner_name=self.scanner_name,
            status=ScannerStatus.DISABLED,
            severity=Severity.LOW.value,
            confidence=0.0,
            evidence=["YARA integration is not enabled in this build"],
            raw_output={"placeholder": True},
        )


class ClamAVScanner(BaseScanner):
    """Placeholder ClamAV integration that stays disabled until wired up."""

    scanner_name = "clamav"
    description = "ClamAV integration placeholder"
    default_enabled = False

    def scan(self, context: ScannerContext) -> ScannerResult:
        return ScannerResult(
            scanner_name=self.scanner_name,
            status=ScannerStatus.DISABLED,
            severity=Severity.LOW.value,
            confidence=0.0,
            evidence=["ClamAV integration is not enabled in this build"],
            raw_output={"placeholder": True},
        )
