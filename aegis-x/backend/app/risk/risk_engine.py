"""
Deterministic risk scoring engine.

This is the SOLE authority for severity in Aegis-X. It evaluates a set
of independent, weighted risk factors against the evidence in a
FileReport and produces a numeric score plus a severity bucket. The AI
layer is never consulted here and has no ability to influence the score
— it only explains factors that this engine has already determined.

Weights are configurable in one place (`RiskEngine.DEFAULT_WEIGHTS`) so
tuning the model doesn't require touching evaluation logic, and new
factors can be added by adding one method + one registry entry.
"""

from __future__ import annotations

from typing import Callable, Dict, List

from app.models.file_report import FileReport, RiskAssessment, RiskFactor, Severity
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Extension categories used purely as risk evidence, not as a blocklist.
_EXECUTABLE_EXTENSIONS = {
    "exe", "dll", "sys", "scr", "com", "msi", "bat", "cmd", "ps1",
    "vbs", "js", "jar", "cpl", "gadget", "hta",
}


class RiskEngine:
    """Deterministic, weighted risk scoring engine."""

    # Weight for each factor, out of an effectively unbounded raw total
    # that is later normalized to 0-100. Tuning these values changes the
    # model's sensitivity without touching evaluation logic.
    DEFAULT_WEIGHTS: Dict[str, float] = {
        "clamav_detection": 100.0,
        "yara_detection": 80.0,
        "filetype_mismatch": 50.0,
        "suspicious_archive": 30.0,
        "unsigned_executable": 20.0,
        "high_entropy": 15.0,
        "is_executable": 8.0,
        "runs_from_downloads": 5.0,
        "aslr_disabled": 12.0,
        "dep_disabled": 12.0,
        "cfg_disabled": 6.0,
        "packed_sections": 15.0,
        "suspicious_imports": 15.0,
        "unknown_publisher": 8.0,
        "executable_extension": 6.0,
        "double_extension": 10.0,
        "invalid_signature": 18.0,
    }

    # Normalizing constant: the maximum plausible raw score
    _MAX_RAW_SCORE = sum(DEFAULT_WEIGHTS.values())

    _SEVERITY_THRESHOLDS: List[tuple] = [
        (75.0, Severity.CRITICAL),
        (50.0, Severity.HIGH),
        (25.0, Severity.MEDIUM),
        (0.0, Severity.LOW),
    ]

    def __init__(self, weights: Dict[str, float] = None) -> None:
        self._weights = weights or dict(self.DEFAULT_WEIGHTS)
        self._evaluators: Dict[str, Callable[[FileReport], tuple]] = {
            "clamav_detection": self._eval_clamav_detection,
            "yara_detection": self._eval_yara_detection,
            "filetype_mismatch": self._eval_filetype_mismatch,
            "suspicious_archive": self._eval_suspicious_archive,
            "unsigned_executable": self._eval_unsigned_executable,
            "high_entropy": self._eval_high_entropy,
            "is_executable": self._eval_is_executable,
            "runs_from_downloads": self._eval_runs_from_downloads,
            "aslr_disabled": self._eval_aslr_disabled,
            "dep_disabled": self._eval_dep_disabled,
            "cfg_disabled": self._eval_cfg_disabled,
            "packed_sections": self._eval_packed_sections,
            "suspicious_imports": self._eval_suspicious_imports,
            "unknown_publisher": self._eval_unknown_publisher,
            "executable_extension": self._eval_executable_extension,
            "double_extension": self._eval_double_extension,
            "invalid_signature": self._eval_invalid_signature,
        }

    def score(self, report: FileReport) -> RiskAssessment:
        """Evaluate every registered factor and produce a RiskAssessment."""
        factors: List[RiskFactor] = []
        raw_total = 0.0
        has_critical_hit = False
        has_high_hit = False

        for name, evaluator in self._evaluators.items():
            triggered, description = evaluator(report)
            weight = self._weights.get(name, 0.0)
            if triggered:
                raw_total += weight
                if name == "clamav_detection":
                    has_critical_hit = True
                elif name == "yara_detection":
                    has_high_hit = True
                elif name == "filetype_mismatch":
                    has_high_hit = True

            factors.append(
                RiskFactor(
                    name=name,
                    description=description,
                    weight=weight,
                    triggered=triggered,
                )
            )

        if has_critical_hit:
            normalized = 100.0
        elif has_high_hit:
            normalized = max(80.0, min(100.0, raw_total))
        else:
            normalized = min(100.0, round(raw_total * 1.5, 2))

        severity = self._severity_for_score(normalized)

        logger.info(
            "Risk score for %s: %.2f (%s)",
            report.metadata.filename,
            normalized,
            severity.value,
        )
        return RiskAssessment(score=normalized, severity=severity, factors=factors)

    def _severity_for_score(self, score: float) -> Severity:
        for threshold, severity in self._SEVERITY_THRESHOLDS:
            if score >= threshold:
                return severity
        return Severity.LOW

    # ------------------------------------------------------------------
    # Individual factor evaluators. Each returns (triggered, description).
    # ------------------------------------------------------------------

    @staticmethod
    def _eval_clamav_detection(report: FileReport) -> tuple:
        if not hasattr(report, 'scanner_results') or not report.scanner_results:
            return False, "ClamAV virus detection: clean"
        for res in report.scanner_results:
            if res.scanner_name == "clamav" and res.detection_count > 0:
                name = ", ".join(res.findings) if res.findings else "malware signature"
                return True, f"ClamAV detected malware: {name}"
        return False, "ClamAV virus detection: clean"

    @staticmethod
    def _eval_yara_detection(report: FileReport) -> tuple:
        if not hasattr(report, 'scanner_results') or not report.scanner_results:
            return False, "YARA rule match: none"
        for res in report.scanner_results:
            if res.scanner_name == "yara" and res.detection_count > 0:
                rules = ", ".join(res.findings) if res.findings else "threat rule"
                return True, f"YARA matched threat rules: {rules}"
        return False, "YARA rule match: none"

    @staticmethod
    def _eval_filetype_mismatch(report: FileReport) -> tuple:
        if report.file_type_info and report.file_type_info.mismatch:
            desc = report.file_type_info.mismatch_description or "detected file content type does not match extension"
            return True, f"File extension mismatch: {desc}"
        return False, "File extension matches detected content type"

    @staticmethod
    def _eval_suspicious_archive(report: FileReport) -> tuple:
        if report.archive_info and (report.archive_info.executable_count > 0 or report.archive_info.executables_inside > 0 or report.archive_info.is_password_protected or report.archive_info.encrypted):
            return True, "Archive contains executable files or encrypted contents"
        return False, "Archive contains no suspicious executables or encryption"

    @staticmethod
    def _eval_unsigned_executable(report: FileReport) -> tuple:
        from app.models.file_report import SignatureStatus

        triggered = (
            report.metadata.is_executable
            and report.signature.status == SignatureStatus.UNSIGNED
        )
        return triggered, "Executable file has no digital signature"

    @staticmethod
    def _eval_high_entropy(report: FileReport) -> tuple:
        entropy = report.metadata.entropy
        triggered = entropy >= 7.2
        return triggered, f"File entropy is {entropy:.2f}/8.0 (packed/encrypted indicator)"

    @staticmethod
    def _eval_is_executable(report: FileReport) -> tuple:
        return report.metadata.is_executable, "File is an executable format"

    @staticmethod
    def _eval_runs_from_downloads(report: FileReport) -> tuple:
        path_lower = report.metadata.absolute_path.lower()
        triggered = report.metadata.is_executable and "download" in path_lower
        return triggered, "Executable is located directly in the Downloads folder"

    @staticmethod
    def _eval_aslr_disabled(report: FileReport) -> tuple:
        if report.pe_info is None:
            return False, "ASLR: not applicable (not a PE file)"
        triggered = not report.pe_info.aslr_enabled
        return triggered, "ASLR (address space layout randomization) is disabled"

    @staticmethod
    def _eval_dep_disabled(report: FileReport) -> tuple:
        if report.pe_info is None:
            return False, "DEP/NX: not applicable (not a PE file)"
        triggered = not report.pe_info.dep_nx_enabled
        return triggered, "DEP/NX (data execution prevention) is disabled"

    @staticmethod
    def _eval_cfg_disabled(report: FileReport) -> tuple:
        if report.pe_info is None:
            return False, "CFG: not applicable (not a PE file)"
        triggered = not report.pe_info.cfg_enabled
        return triggered, "Control Flow Guard is disabled"

    @staticmethod
    def _eval_packed_sections(report: FileReport) -> tuple:
        if report.pe_info is None:
            return False, "Sections: not applicable (not a PE file)"
        triggered = len(report.pe_info.suspicious_sections) > 0
        names = ", ".join(report.pe_info.suspicious_sections) or "none"
        return triggered, f"Non-standard or writable+executable sections found: {names}"

    @staticmethod
    def _eval_suspicious_imports(report: FileReport) -> tuple:
        if report.pe_info is None:
            return False, "Imports: not applicable (not a PE file)"
        triggered = len(report.pe_info.suspicious_imports) > 0
        names = ", ".join(report.pe_info.suspicious_imports) or "none"
        return triggered, f"Imports commonly associated with injection/evasion: {names}"

    @staticmethod
    def _eval_unknown_publisher(report: FileReport) -> tuple:
        triggered = report.metadata.is_executable and not report.signature.publisher
        return triggered, "No identifiable publisher for this executable"

    @staticmethod
    def _eval_executable_extension(report: FileReport) -> tuple:
        triggered = report.metadata.extension in _EXECUTABLE_EXTENSIONS
        return triggered, f"File extension '.{report.metadata.extension}' is executable-capable"

    @staticmethod
    def _eval_double_extension(report: FileReport) -> tuple:
        # e.g. "invoice.pdf.exe" — a classic social engineering trick.
        name_parts = report.metadata.filename.lower().split(".")
        triggered = (
            len(name_parts) >= 3
            and name_parts[-1] in _EXECUTABLE_EXTENSIONS
        )
        return triggered, "Filename contains a suspicious double extension"

    @staticmethod
    def _eval_invalid_signature(report: FileReport) -> tuple:
        from app.models.file_report import SignatureStatus

        triggered = report.signature.status == SignatureStatus.SIGNED_INVALID
        return triggered, "File has an invalid or untrusted digital signature"
