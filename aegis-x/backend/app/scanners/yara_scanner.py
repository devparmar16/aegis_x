"""
YARA signature scanner for matching custom rules against files.

Loads all .yar/.yara files from the configured directory.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

from app.config.config import AppConfig
from app.models.scanner_result import ScannerResult, ScannerStatus
from app.scanners.base import BaseScanner, ScannerContext
from app.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False


class YaraScanner(BaseScanner):
    """Matches compiled YARA rules against file content."""

    scanner_name = "yara"
    description = "YARA rule matching"
    default_enabled = True

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self._rules: Optional[yara.Rules] = None
        self._compile_error: Optional[str] = None
        self._compile_rules()

    def health_check(self) -> bool:
        """Returns True if yara-python is installed and rules are compiled."""
        return _YARA_AVAILABLE and self.config.yara_enabled and self._rules is not None

    def _compile_rules(self) -> None:
        if not _YARA_AVAILABLE or not self.config.yara_enabled:
            return

        rules_dir = Path(self.config.yara_rules_dir)
        if not rules_dir.exists() or not rules_dir.is_dir():
            self._compile_error = f"YARA rules directory not found: {rules_dir}"
            logger.warning(self._compile_error)
            return

        rule_files: Dict[str, str] = {}
        for root, _, files in os.walk(rules_dir):
            for file in files:
                if file.endswith((".yar", ".yara")):
                    filepath = Path(root) / file
                    # Provide a namespace using the relative path so rule name collisions are less likely
                    namespace = str(filepath.relative_to(rules_dir).with_suffix(""))
                    rule_files[namespace] = str(filepath)

        if not rule_files:
            self._compile_error = f"No .yar/.yara files found in {rules_dir}"
            logger.info("YARA is enabled but no rules were found. Scanner will return SKIPPED.")
            return

        try:
            self._rules = yara.compile(filepaths=rule_files)
            logger.info("Successfully compiled %d YARA rule files.", len(rule_files))
        except yara.SyntaxError as exc:
            self._compile_error = f"YARA syntax error during compilation: {exc}"
            logger.error(self._compile_error)
        except Exception as exc:
            self._compile_error = f"Unexpected error compiling YARA rules: {exc}"
            logger.error(self._compile_error)

    def scan(self, context: ScannerContext) -> ScannerResult:
        if not self.config.yara_enabled:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.DISABLED,
                severity="Low",
                confidence=0.0,
                evidence=["YARA scanning is disabled in configuration"],
            )

        if not _YARA_AVAILABLE:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.UNAVAILABLE,
                severity="Low",
                confidence=0.0,
                evidence=["yara-python is not installed"],
            )

        if self._rules is None:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.WARNING,
                severity="Low",
                confidence=0.0,
                evidence=["YARA rules failed to compile or none were found"],
                errors=[self._compile_error] if self._compile_error else ["No rules found"],
            )

        try:
            matches = self._rules.match(str(context.file_path))
        except Exception as exc:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.FAILURE,
                severity="High",
                confidence=0.0,
                evidence=["Failed to scan file with YARA"],
                errors=[str(exc)],
            )

        if not matches:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.SUCCESS,
                severity="Low",
                confidence=0.9,
                evidence=["No YARA rules matched"],
                detection_count=0,
            )

        # Format matches
        findings = []
        evidence = []
        match_details = []
        
        for match in matches:
            findings.append(f"YARA_{match.rule}")
            evidence.append(f"Matched rule: {match.rule} (Namespace: {match.namespace})")
            match_details.append({
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": match.meta,
                # String matching results might be huge, omitted for brevity
            })

        return ScannerResult(
            scanner_name=self.scanner_name,
            status=ScannerStatus.SUCCESS,
            severity="High",  # A matched YARA rule is usually a high severity finding
            confidence=1.0,
            findings=findings,
            evidence=evidence,
            raw_output={"matches": match_details},
            detection_count=len(matches),
        )
