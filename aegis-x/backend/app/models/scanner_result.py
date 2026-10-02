"""Common result model returned by every scanner engine plugin."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScannerStatus(str, Enum):
    """Lifecycle outcome for a scanner run."""

    SUCCESS = "success"
    WARNING = "warning"
    FAILURE = "failure"
    SKIPPED = "skipped"
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"  # dependency missing (ClamAV not installed, etc.)


class ScannerResult(BaseModel):
    """Independent findings from one scanner plugin.

    `findings` carries structured finding names (e.g. 'YARA:Mimikatz').
    `evidence` carries human-readable evidence strings.
    They are complementary, not duplicates.
    """

    scanner_name: str
    scanner_version: Optional[str] = None
    status: ScannerStatus = ScannerStatus.SUCCESS
    execution_time_ms: float = 0.0
    severity: str = "Low"
    confidence: float = 0.0
    findings: List[str] = Field(default_factory=list)   # structured finding names
    evidence: List[str] = Field(default_factory=list)   # human-readable evidence
    raw_output: Optional[Dict[str, Any]] = None
    errors: List[str] = Field(default_factory=list)
    detection_count: int = 0
    enabled: bool = True
