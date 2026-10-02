"""Evidence aggregation for scanner results."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

from app.models.file_report import FileReport, Severity
from app.models.scanner_result import ScannerResult, ScannerStatus


class EvidenceAggregator:
    """Combines scanner outputs into a single evidence summary."""

    def aggregate(self, report: FileReport, scanner_results: List[ScannerResult]) -> Dict[str, Any]:
        findings = []
        errors = []
        severities = []
        enabled_scanners = 0

        for result in scanner_results:
            if result.enabled:
                enabled_scanners += 1
            if result.status in {ScannerStatus.SUCCESS, ScannerStatus.WARNING} and result.evidence:
                findings.extend(result.evidence)
            if result.errors:
                errors.extend(result.errors)
            severities.append(result.severity)

        severity_counts = Counter(severities)
        top_severity = Severity.LOW.value
        for candidate in (Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value, Severity.LOW.value):
            if severity_counts.get(candidate, 0):
                top_severity = candidate
                break

        summary = {
            "scanner_count": len(scanner_results),
            "enabled_scanner_count": enabled_scanners,
            "finding_count": len(findings),
            "error_count": len(errors),
            "top_scanner_severity": top_severity,
            "scanner_severity_counts": dict(severity_counts),
            "findings": findings[:100],
            "errors": errors[:100],
            "file": report.metadata.filename,
        }
        return summary
