"""
System-level evidence models for Aegis-X endpoint exposure subsystem.

These models represent running processes, Windows services, persistence
entries, network exposure, and investigation findings. All fields are
optional-safe so partial enumeration (e.g. permission-denied process
details) never crashes collection.

IMPORTANT: The system enumeration subsystem is READ-ONLY. These models
carry evidence only -- no mutation of system state ever occurs.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PersistenceLocation(str, Enum):
    """Where a persistence entry lives."""

    REGISTRY_RUN = "registry_run"
    REGISTRY_RUN_ONCE = "registry_run_once"
    REGISTRY_RUN_USER = "registry_run_user"
    STARTUP_FOLDER = "startup_folder"
    STARTUP_FOLDER_USER = "startup_folder_user"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    OTHER = "other"


class RelationshipType(str, Enum):
    """Evidence-based relationship between a finding and a system resource.

    POTENTIALLY_AFFECTED is always an inference and must be marked as such
    in any finding that uses it.
    """

    DETECTED = "Detected"
    RUNNING = "Running"
    ASSOCIATED = "Associated"
    CREATED = "Created"
    MODIFIED = "Modified"
    EXECUTED_FROM = "Executed From"
    LISTENING_ON = "Listening On"
    INSTALLED_AS = "Installed As"
    PERSISTENCE_ENTRY = "Persistence Entry"
    POTENTIALLY_AFFECTED = "Potentially Affected"  # inference — mark clearly


class FindingStatus(str, Enum):
    """Lifecycle status of an investigation finding."""

    NEW = "New"
    ACTIVE = "Active"
    RESOLVED = "Resolved"
    ACKNOWLEDGED = "Acknowledged"


class FindingType(str, Enum):
    """Category of an investigation finding."""

    MALWARE_DETECTED = "malware_detected"
    SUSPICIOUS_FILE = "suspicious_file"
    TYPE_MISMATCH = "type_mismatch"
    UNSIGNED_EXECUTABLE = "unsigned_executable"
    INVALID_SIGNATURE = "invalid_signature"
    HIGH_ENTROPY = "high_entropy"
    SUSPICIOUS_PROCESS = "suspicious_process"
    SUSPICIOUS_SERVICE = "suspicious_service"
    PERSISTENCE_DETECTED = "persistence_detected"
    NETWORK_EXPOSURE = "network_exposure"
    YARA_MATCH = "yara_match"
    SUSPICIOUS_ARCHIVE = "suspicious_archive"
    SUSPICIOUS_IMPORT = "suspicious_import"
    SERVICE_IN_SUSPICIOUS_PATH = "service_in_suspicious_path"
    UNSIGNED_SERVICE_BINARY = "unsigned_service_binary"
    CLAMAV_DETECTION = "clamav_detection"


# ---------------------------------------------------------------------------
# Network connection sub-model
# ---------------------------------------------------------------------------


class NetworkConnection(BaseModel):
    """One network connection belonging to a process."""

    protocol: str = "unknown"
    local_address: Optional[str] = None
    local_port: Optional[int] = None
    remote_address: Optional[str] = None
    remote_port: Optional[int] = None
    status: Optional[str] = None


# ---------------------------------------------------------------------------
# Running process
# ---------------------------------------------------------------------------


class RunningProcess(BaseModel):
    """Evidence snapshot of a single running process.

    Collected by ProcessCollector via psutil. Never modified — read-only.
    """

    pid: int
    name: str
    exe_path: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    username: Optional[str] = None
    is_elevated: Optional[bool] = None
    cmdline: Optional[str] = None
    created_time: Optional[datetime] = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    connections: List[NetworkConnection] = Field(default_factory=list)
    enumerated_at: datetime = Field(default_factory=datetime.utcnow)
    # Set by correlator when this process matches a scanned file
    associated_file_report_id: Optional[int] = None
    db_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Windows service
# ---------------------------------------------------------------------------


class WindowsService(BaseModel):
    """Evidence snapshot of a single Windows service.

    Collected by ServiceCollector via winreg + psutil. Read-only.
    """

    service_name: str
    display_name: str = ""
    status: str = "unknown"
    start_type: str = "unknown"
    exe_path: Optional[str] = None
    service_account: Optional[str] = None
    pid: Optional[int] = None
    description: Optional[str] = None

    # Risk flags — structural observations, not verdicts
    is_system_account: bool = False     # SYSTEM / LocalSystem
    is_autostart: bool = False           # starts at boot
    exe_in_suspicious_path: bool = False  # user-writable location
    exe_is_unsigned: Optional[bool] = None  # None = not checked

    enumerated_at: datetime = Field(default_factory=datetime.utcnow)
    associated_file_report_id: Optional[int] = None
    db_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Persistence entry
# ---------------------------------------------------------------------------


class PersistenceEntry(BaseModel):
    """One persistence mechanism observed on the endpoint.

    Collected by PersistenceCollector from registry Run keys, startup
    folders, and scheduled tasks. Read-only.
    """

    location: PersistenceLocation
    location_path: str          # registry key path or folder path or task name
    name: str                   # value name or task name or filename
    command: Optional[str] = None
    exe_path: Optional[str] = None
    user_context: Optional[str] = None   # HKCU = current user, HKLM = all users
    privilege: Optional[str] = None      # SYSTEM / user
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    associated_file_report_id: Optional[int] = None
    db_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Network exposure
# ---------------------------------------------------------------------------


class NetworkExposure(BaseModel):
    """A listening port on the endpoint.

    Collected by NetworkCollector via psutil. Read-only. Non-loopback
    listeners are flagged for review.
    """

    protocol: str
    local_address: str
    local_port: int
    remote_address: Optional[str] = None
    remote_port: Optional[int] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    exe_path: Optional[str] = None
    is_external_facing: bool = False   # True when local_address != 127.x
    enumerated_at: datetime = Field(default_factory=datetime.utcnow)
    associated_file_report_id: Optional[int] = None
    db_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Investigation finding
# ---------------------------------------------------------------------------


class InvestigationFinding(BaseModel):
    """Persisted, historically-tracked security finding.

    Never auto-deleted. Status transitions:
        NEW → ACTIVE → ACKNOWLEDGED → RESOLVED

    When relationship_type == POTENTIALLY_AFFECTED, is_inference MUST be
    True. The UI must display inference findings with a clear disclaimer.
    """

    finding_id: Optional[int] = None
    first_detected: datetime = Field(default_factory=datetime.utcnow)
    last_observed: datetime = Field(default_factory=datetime.utcnow)

    # Source references
    file_report_id: Optional[int] = None
    scanner: Optional[str] = None

    # Classification
    severity: str = "Low"
    confidence: float = 0.5
    finding_type: FindingType = FindingType.SUSPICIOUS_FILE

    # Human-readable
    description: str = ""
    evidence: List[str] = Field(default_factory=list)

    # Affected resource
    resource_type: Optional[str] = None   # e.g. "process", "service", "file"
    resource_path: Optional[str] = None
    pid: Optional[int] = None
    service_name: Optional[str] = None
    network_endpoint: Optional[str] = None

    # Relationship (evidence-based)
    relationship_type: RelationshipType = RelationshipType.DETECTED
    is_inference: bool = False   # MUST be True when POTENTIALLY_AFFECTED

    # Lifecycle
    status: FindingStatus = FindingStatus.NEW
    user_acknowledgement: Optional[str] = None
