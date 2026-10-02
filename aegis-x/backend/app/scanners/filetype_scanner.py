"""
Scanner that evaluates FileTypeInfo for mismatches.

A mismatch between a file's extension and its content (magic bytes)
is often a strong indicator of social engineering (e.g. invoice.pdf.exe).
"""

from __future__ import annotations

from app.models.scanner_result import ScannerResult, ScannerStatus
from app.scanners.base import BaseScanner, ScannerContext


class FiletypeScanner(BaseScanner):
    """Flags files where the extension does not match the actual content type."""

    scanner_name = "FileType Mismatch"
    description = "Detects files masking their true format via false extensions."

    def scan(self, context: ScannerContext) -> ScannerResult:
        if not context.report.file_type_info:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.SKIPPED,
                severity="Low",
                evidence=["No file type info available in report."],
            )

        info = context.report.file_type_info

        if not info.mismatch:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.SUCCESS,
                severity="Low",
                evidence=["Extension matches detected file content type."],
            )

        return ScannerResult(
            scanner_name=self.scanner_name,
            status=ScannerStatus.WARNING,
            severity="High",
            confidence=0.9,
            findings=["TYPE_MISMATCH"],
            evidence=[info.mismatch_description or "File extension and format mismatch detected."],
            raw_output={"magic_bytes_hex": info.magic_bytes_hex, "actual_format": info.actual_format},
            detection_count=1,
        )
