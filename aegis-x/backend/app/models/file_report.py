"""
Domain models for Aegis-X's File Security Scanner and Endpoint Exposure subsystems.

These models are the shared contract passed between collectors, scanners, the risk
engine, the AI layer, the database, and the UI. Keeping them here (rather than
letting each layer define its own shape) is what keeps the layers decoupled.

Model evolution policy:
- Add new Optional fields freely (backward compatible with existing DB rows).
- Never remove or rename fields without a DB migration.
- Keep to_evidence_dict() in sync when adding new sections.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.models.scanner_result import ScannerResult


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Deterministic risk severity levels produced by the risk engine."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------


class SignatureStatus(str, Enum):
    """Digital signature verification status."""

    SIGNED_VALID = "signed_valid"
    SIGNED_INVALID = "signed_invalid"
    UNSIGNED = "unsigned"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"   # non-PE formats (.txt, .jpg, .zip…)


class SignatureInfo(BaseModel):
    """Digital signature / publisher evidence."""

    status: SignatureStatus = SignatureStatus.UNKNOWN
    publisher: Optional[str] = None
    detail: Optional[str] = None
    certificate_info: Optional[Dict[str, Any]] = None   # subject, issuer, thumbprint


# ---------------------------------------------------------------------------
# File metadata
# ---------------------------------------------------------------------------


class FileMetadata(BaseModel):
    """Basic filesystem-level evidence about a scanned file."""

    filename: str
    extension: str
    absolute_path: str
    size_bytes: int
    created_time: datetime
    modified_time: datetime
    mime_type: str
    entropy: float
    is_executable: bool


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------


class HashInfo(BaseModel):
    """Cryptographic identity of the file. SHA-256 is the primary identifier."""

    sha256: str
    sha1: str = ""
    md5: str


# ---------------------------------------------------------------------------
# File type / extension mismatch
# ---------------------------------------------------------------------------


class FileTypeInfo(BaseModel):
    """Evidence from content-based file type detection.

    A mismatch between the file extension and the detected actual format
    (e.g. photo.jpg whose magic bytes indicate MZ PE) is a significant
    risk indicator and must produce a finding.
    """

    extension: str = ""
    detected_mime: str = ""
    detected_type: str = ""
    magic_bytes_hex: str = ""          # first 8 bytes in hex
    actual_format: str = ""
    mismatch: bool = False
    mismatch_description: Optional[str] = None


# ---------------------------------------------------------------------------
# PE header
# ---------------------------------------------------------------------------


class PESectionInfo(BaseModel):
    """Per-section PE evidence including entropy."""

    name: str
    virtual_address: Optional[str] = None
    raw_size: int = 0
    entropy: float = 0.0
    is_executable: bool = False
    is_writable: bool = False
    is_suspicious: bool = False


class PEHeaderInfo(BaseModel):
    """Evidence extracted from the PE header when the file is a Windows
    executable/DLL. All fields are Optional because this model is simply
    omitted (left as None on the parent) for non-PE files.
    """

    architecture: Optional[str] = None
    is_dll: bool = False
    is_driver: bool = False
    timestamp: Optional[datetime] = None
    entry_point: Optional[str] = None     # hex string
    image_base: Optional[str] = None      # hex string
    subsystem: Optional[str] = None
    subsystem_value: Optional[int] = None
    pe_characteristics: Optional[int] = None

    # Security features
    aslr_enabled: bool = False
    dep_nx_enabled: bool = False
    cfg_enabled: bool = False

    # Sections
    sections: List[PESectionInfo] = Field(default_factory=list)
    section_names: List[str] = Field(default_factory=list)
    section_entropy: Dict[str, float] = Field(default_factory=dict)  # name→entropy
    suspicious_sections: List[str] = Field(default_factory=list)

    # Imports / exports
    imports: List[str] = Field(default_factory=list)
    exports: List[str] = Field(default_factory=list)
    dll_dependencies: List[str] = Field(default_factory=list)
    suspicious_imports: List[str] = Field(default_factory=list)

    compiler_hint: Optional[str] = None
    executable_type: Optional[str] = None  # EXE, DLL, SYS, CUI, GUI


# ---------------------------------------------------------------------------
# Archive
# ---------------------------------------------------------------------------


class ArchiveEntry(BaseModel):
    """Represents a single file entry inside an archive."""

    filename: str = ""
    path: str = ""
    size_bytes: int = 0
    compressed_size_bytes: int = 0
    is_encrypted: bool = False
    encrypted: bool = False
    is_directory: bool = False
    is_executable: bool = False

    def model_post_init(self, __context: Any) -> None:
        if not self.filename and self.path:
            object.__setattr__(self, "filename", self.path)
        if not self.path and self.filename:
            object.__setattr__(self, "path", self.filename)
        if self.encrypted and not self.is_encrypted:
            object.__setattr__(self, "is_encrypted", True)


class ArchiveInfo(BaseModel):
    """Evidence collected from archive inspection."""

    is_archive: bool = True
    format: str = "zip"
    encrypted: bool = False
    is_password_protected: bool = False
    total_entries: int = 0
    total_files: int = 0
    filenames: List[str] = Field(default_factory=list)
    extensions: List[str] = Field(default_factory=list)
    has_nested_archives: bool = False
    nested_archives: int = 0
    nested_archive_names: List[str] = Field(default_factory=list)
    executable_count: int = 0
    executables_inside: int = 0
    dll_count: int = 0
    script_count: int = 0
    powershell_count: int = 0
    javascript_count: int = 0
    office_count: int = 0
    suspicious_filenames: List[str] = Field(default_factory=list)
    compression_ratio: Optional[float] = None
    uncompressed_size: Optional[int] = None
    entries: List[ArchiveEntry] = Field(default_factory=list)
    max_depth_reached: int = 1
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Threat intelligence
# ---------------------------------------------------------------------------


class ThreatIntelResult(BaseModel):
    """Result from a threat intelligence provider hash lookup.

    status values: 'clean', 'malicious', 'suspicious', 'not_found',
                   'unavailable', 'error'
    """

    provider: str = "none"
    sha256: str = ""
    status: str = "unavailable"
    found: Optional[bool] = None
    malicious: Optional[bool] = None
    detection_names: List[str] = Field(default_factory=list)
    raw_response: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------


class RiskFactor(BaseModel):
    """One weighted contributor to the overall risk score."""

    name: str
    description: str
    weight: float
    triggered: bool


class RiskAssessment(BaseModel):
    """Output of the deterministic risk engine. The AI never sets this."""

    score: float
    severity: Severity
    factors: List[RiskFactor]


# ---------------------------------------------------------------------------
# AI explanation
# ---------------------------------------------------------------------------


class AIExplanation(BaseModel):
    """Non-authoritative, explanatory output from the AI layer.

    The AI never assigns severity or score; it only explains evidence
    that the risk engine already collected and scored.
    """

    provider: str
    model: str
    what_it_appears_to_be: str
    why_evidence_matters: str
    possible_attack_techniques: str
    potential_impact: str
    recommended_precautions: str
    confidence_level: str
    raw_response: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# File report (unified)
# ---------------------------------------------------------------------------


class FileReport(BaseModel):
    """The complete, aggregated report for a single analyzed file."""

    report_id: Optional[int] = None
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)

    # Collected evidence
    metadata: FileMetadata
    hashes: HashInfo
    signature: SignatureInfo
    pe_info: Optional[PEHeaderInfo] = None
    file_type_info: Optional[FileTypeInfo] = None
    archive_info: Optional[ArchiveInfo] = None
    threat_intel_result: Optional[ThreatIntelResult] = None

    # Analysis results
    risk: Optional[RiskAssessment] = None
    ai_explanation: Optional[AIExplanation] = None
    scanner_results: List[ScannerResult] = Field(default_factory=list)
    scanner_summary: Dict[str, Any] = Field(default_factory=dict)

    def to_evidence_dict(self) -> Dict[str, Any]:
        """Flatten the report into a plain dict suitable for prompting the
        AI layer or for the risk engine — evidence only, no verdicts.
        """
        return {
            "metadata": self.metadata.model_dump(mode="json"),
            "hashes": self.hashes.model_dump(mode="json"),
            "signature": self.signature.model_dump(mode="json"),
            "pe_info": self.pe_info.model_dump(mode="json") if self.pe_info else None,
            "file_type_info": self.file_type_info.model_dump(mode="json") if self.file_type_info else None,
            "archive_info": self.archive_info.model_dump(mode="json") if self.archive_info else None,
            "threat_intel": self.threat_intel_result.model_dump(mode="json") if self.threat_intel_result else None,
            "scanner_results": [result.model_dump(mode="json") for result in self.scanner_results],
            "scanner_summary": self.scanner_summary,
        }
