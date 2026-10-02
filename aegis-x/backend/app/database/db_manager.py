"""SQLite persistence layer for Aegis-X.

Covers: file reports, scanner results, watched folders, settings,
scan history, system enumeration snapshots, and investigation findings.

Schema upgrades are additive only (CREATE TABLE IF NOT EXISTS + ALTER TABLE
via _safe_add_column). No data is ever automatically deleted.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

from app.models.file_report import FileReport, Severity
from app.models.scanner_result import ScannerResult, ScannerStatus
from app.models.system_models import (
    FindingStatus,
    FindingType,
    InvestigationFinding,
    NetworkExposure,
    PersistenceEntry,
    PersistenceLocation,
    RelationshipType,
    RunningProcess,
    WindowsService,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS file_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analyzed_at TEXT NOT NULL,
    filename TEXT NOT NULL,
    extension TEXT,
    absolute_path TEXT NOT NULL,
    size_bytes INTEGER,
    sha256 TEXT,
    sha1 TEXT,
    md5 TEXT,
    mime_type TEXT,
    entropy REAL,
    is_executable INTEGER,
    signature_status TEXT,
    publisher TEXT,
    risk_score REAL,
    risk_severity TEXT,
    ai_provider TEXT,
    ai_confidence TEXT,
    report_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_file_reports_sha256 ON file_reports (sha256);
CREATE INDEX IF NOT EXISTS idx_file_reports_analyzed_at ON file_reports (analyzed_at);
CREATE INDEX IF NOT EXISTS idx_file_reports_risk_severity ON file_reports (risk_severity);

CREATE TABLE IF NOT EXISTS scanner_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    scanner_name TEXT NOT NULL,
    scanner_version TEXT,
    status TEXT NOT NULL,
    execution_time_ms REAL NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    findings_json TEXT,
    evidence_json TEXT NOT NULL,
    raw_output_json TEXT,
    errors_json TEXT,
    detection_count INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    FOREIGN KEY (report_id) REFERENCES file_reports (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scanner_results_report_id ON scanner_results (report_id);
CREATE INDEX IF NOT EXISTS idx_scanner_results_scanner_name ON scanner_results (scanner_name);

CREATE TABLE IF NOT EXISTS scanner_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    scanner_name TEXT NOT NULL,
    error_message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (report_id) REFERENCES file_reports (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS watched_folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    folder_path TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_watched_folders_enabled ON watched_folders (enabled);

CREATE TABLE IF NOT EXISTS app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    target_path TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT,
    report_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_history_started_at ON scan_history (started_at);

-- -----------------------------------------------------------------------
-- System enumeration tables
-- -----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS running_processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    name TEXT NOT NULL,
    exe_path TEXT,
    parent_pid INTEGER,
    parent_name TEXT,
    username TEXT,
    is_elevated INTEGER,
    cmdline TEXT,
    created_time TEXT,
    cpu_percent REAL,
    memory_mb REAL,
    connections_json TEXT,
    associated_file_report_id INTEGER,
    enumerated_at TEXT NOT NULL,
    FOREIGN KEY (associated_file_report_id) REFERENCES file_reports (id)
);

CREATE INDEX IF NOT EXISTS idx_running_processes_pid ON running_processes (pid);
CREATE INDEX IF NOT EXISTS idx_running_processes_enumerated_at ON running_processes (enumerated_at);

CREATE TABLE IF NOT EXISTS windows_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT NOT NULL,
    display_name TEXT,
    status TEXT,
    start_type TEXT,
    exe_path TEXT,
    service_account TEXT,
    pid INTEGER,
    description TEXT,
    is_system_account INTEGER DEFAULT 0,
    is_autostart INTEGER DEFAULT 0,
    exe_in_suspicious_path INTEGER DEFAULT 0,
    associated_file_report_id INTEGER,
    enumerated_at TEXT NOT NULL,
    FOREIGN KEY (associated_file_report_id) REFERENCES file_reports (id)
);

CREATE INDEX IF NOT EXISTS idx_windows_services_service_name ON windows_services (service_name);

CREATE TABLE IF NOT EXISTS persistence_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    location TEXT NOT NULL,
    location_path TEXT NOT NULL,
    name TEXT NOT NULL,
    command TEXT,
    exe_path TEXT,
    user_context TEXT,
    privilege TEXT,
    detected_at TEXT NOT NULL,
    associated_file_report_id INTEGER,
    FOREIGN KEY (associated_file_report_id) REFERENCES file_reports (id)
);

CREATE INDEX IF NOT EXISTS idx_persistence_entries_location ON persistence_entries (location);

CREATE TABLE IF NOT EXISTS network_exposures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol TEXT NOT NULL,
    local_address TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    remote_address TEXT,
    remote_port INTEGER,
    pid INTEGER,
    process_name TEXT,
    exe_path TEXT,
    is_external_facing INTEGER DEFAULT 0,
    associated_file_report_id INTEGER,
    enumerated_at TEXT NOT NULL,
    FOREIGN KEY (associated_file_report_id) REFERENCES file_reports (id)
);

CREATE INDEX IF NOT EXISTS idx_network_exposures_local_port ON network_exposures (local_port);

CREATE TABLE IF NOT EXISTS investigation_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_detected TEXT NOT NULL,
    last_observed TEXT NOT NULL,
    file_report_id INTEGER,
    scanner TEXT,
    severity TEXT NOT NULL DEFAULT 'Low',
    confidence REAL NOT NULL DEFAULT 0.5,
    finding_type TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_json TEXT,
    resource_type TEXT,
    resource_path TEXT,
    pid INTEGER,
    service_name TEXT,
    network_endpoint TEXT,
    relationship_type TEXT NOT NULL DEFAULT 'Detected',
    is_inference INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'New',
    user_acknowledgement TEXT,
    FOREIGN KEY (file_report_id) REFERENCES file_reports (id)
);

CREATE INDEX IF NOT EXISTS idx_investigation_findings_status ON investigation_findings (status);
CREATE INDEX IF NOT EXISTS idx_investigation_findings_severity ON investigation_findings (severity);
CREATE INDEX IF NOT EXISTS idx_investigation_findings_file_report_id ON investigation_findings (file_report_id);

CREATE TABLE IF NOT EXISTS system_scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    process_count INTEGER DEFAULT 0,
    service_count INTEGER DEFAULT 0,
    persistence_count INTEGER DEFAULT 0,
    network_count INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',
    error TEXT
);
"""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WatchedFolder:
    id: int
    folder_path: str
    enabled: bool
    created_at: str
    updated_at: str


# ---------------------------------------------------------------------------
# DatabaseManager
# ---------------------------------------------------------------------------


class DatabaseManager:
    """Handles persistence for all Aegis-X subsystems."""

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self._database_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _utc_now() -> str:
        return datetime.utcnow().isoformat()

    @staticmethod
    def _report_from_row(row: sqlite3.Row) -> FileReport:
        report = FileReport.model_validate(json.loads(row["report_json"]))
        report.report_id = row["id"]
        return report

    def _initialize_schema(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(_SCHEMA)
                # Check for missing columns from older database files
                cursor = conn.execute("PRAGMA table_info(scanner_results)")
                columns = [col["name"] for col in cursor.fetchall()]
                if "scanner_version" not in columns:
                    conn.execute("ALTER TABLE scanner_results ADD COLUMN scanner_version TEXT")
                if "findings_json" not in columns:
                    conn.execute("ALTER TABLE scanner_results ADD COLUMN findings_json TEXT")

                cursor = conn.execute("PRAGMA table_info(file_reports)")
                fr_columns = [col["name"] for col in cursor.fetchall()]
                if "sha1" not in fr_columns:
                    conn.execute("ALTER TABLE file_reports ADD COLUMN sha1 TEXT")
        except sqlite3.Error as exc:
            logger.error("Failed to initialize database schema: %s", exc)
            raise

    # ------------------------------------------------------------------
    # File Reports
    # ------------------------------------------------------------------

    def save_report(self, report: FileReport) -> Optional[int]:
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO file_reports (
                        analyzed_at, filename, extension, absolute_path,
                        size_bytes, sha256, sha1, md5, mime_type, entropy,
                        is_executable, signature_status, publisher,
                        risk_score, risk_severity, ai_provider,
                        ai_confidence, report_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report.analyzed_at.isoformat(),
                        report.metadata.filename,
                        report.metadata.extension,
                        report.metadata.absolute_path,
                        report.metadata.size_bytes,
                        report.hashes.sha256,
                        report.hashes.sha1,
                        report.hashes.md5,
                        report.metadata.mime_type,
                        report.metadata.entropy,
                        int(report.metadata.is_executable),
                        report.signature.status.value,
                        report.signature.publisher,
                        report.risk.score if report.risk else None,
                        report.risk.severity.value if report.risk else None,
                        report.ai_explanation.provider if report.ai_explanation else None,
                        report.ai_explanation.confidence_level if report.ai_explanation else None,
                        report.model_dump_json(),
                    ),
                )
                return cursor.lastrowid
        except sqlite3.Error as exc:
            logger.error("Failed to save report for %s: %s", report.metadata.filename, exc)
            return None

    def save_scanner_results(self, report_id: int, report: FileReport) -> None:
        if not report.scanner_results:
            return
        try:
            with self._connect() as conn:
                for result in report.scanner_results:
                    conn.execute(
                        """
                        INSERT INTO scanner_results (
                            report_id, file_path, scanner_name, scanner_version, status,
                            execution_time_ms, severity, confidence,
                            findings_json, evidence_json, raw_output_json, errors_json,
                            detection_count, enabled, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            report_id,
                            report.metadata.absolute_path,
                            result.scanner_name,
                            result.scanner_version,
                            result.status.value,
                            result.execution_time_ms,
                            result.severity,
                            result.confidence,
                            json.dumps(result.findings),
                            json.dumps(result.evidence),
                            json.dumps(result.raw_output, default=str) if result.raw_output is not None else None,
                            json.dumps(result.errors) if result.errors else None,
                            result.detection_count,
                            int(result.enabled),
                            self._utc_now(),
                        ),
                    )
                    for error_message in result.errors:
                        conn.execute(
                            """
                            INSERT INTO scanner_errors (
                                report_id, scanner_name, error_message, created_at
                            ) VALUES (?, ?, ?, ?)
                            """,
                            (report_id, result.scanner_name, error_message, self._utc_now()),
                        )
        except sqlite3.Error as exc:
            logger.error("Failed to save scanner results for report %s: %s", report_id, exc)

    def get_report_by_id(self, report_id: int) -> Optional[FileReport]:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT id, report_json FROM file_reports WHERE id = ?", (report_id,)
                ).fetchone()
                if row is None:
                    return None
                report = self._report_from_row(row)
                report.scanner_results = self.list_scanner_results_for_report(report_id)
                report.scanner_summary = self._scanner_summary_from_results(report.scanner_results)
                return report
        except sqlite3.Error as exc:
            logger.error("Failed to fetch report %s: %s", report_id, exc)
            return None

    def list_recent_reports(self, limit: int = 50) -> List[FileReport]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id, report_json
                    FROM file_reports
                    ORDER BY analyzed_at DESC, id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
                reports = [self._report_from_row(row) for row in rows]
                for report in reports:
                    report.scanner_results = self.list_scanner_results_for_report(report.report_id or 0)
                    report.scanner_summary = self._scanner_summary_from_results(report.scanner_results)
                return reports
        except sqlite3.Error as exc:
            logger.error("Failed to list recent reports: %s", exc)
            return []

    def list_file_rows(self, limit: int = 2000, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Return lightweight rows for the Files table (no full report_json parse)."""
        try:
            with self._connect() as conn:
                where_clauses = []
                params: List[Any] = []

                if filters:
                    if filters.get("severity"):
                        where_clauses.append("risk_severity = ?")
                        params.append(filters["severity"])
                    if filters.get("date_from"):
                        where_clauses.append("analyzed_at >= ?")
                        params.append(filters["date_from"])
                    if filters.get("search"):
                        term = f"%{filters['search']}%"
                        where_clauses.append("(filename LIKE ? OR absolute_path LIKE ? OR sha256 LIKE ?)")
                        params.extend([term, term, term])

                where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
                params.append(limit)

                rows = conn.execute(
                    f"""
                    SELECT id, analyzed_at, filename, extension, absolute_path,
                           size_bytes, risk_score, risk_severity, mime_type,
                           publisher, sha256, sha1, signature_status, report_json
                    FROM file_reports
                    {where_sql}
                    ORDER BY analyzed_at DESC, id DESC
                    LIMIT ?
                    """,
                    params,
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            logger.error("Failed to list file rows: %s", exc)
            return []

    def list_scanner_results_for_report(self, report_id: int) -> List[ScannerResult]:
        if not report_id:
            return []
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT scanner_name, scanner_version, status, execution_time_ms, severity,
                           confidence, findings_json, evidence_json, raw_output_json,
                           errors_json, detection_count, enabled
                    FROM scanner_results
                    WHERE report_id = ?
                    ORDER BY id ASC
                    """,
                    (report_id,),
                ).fetchall()
                results: List[ScannerResult] = []
                for row in rows:
                    results.append(
                        ScannerResult(
                            scanner_name=row["scanner_name"],
                            scanner_version=row["scanner_version"],
                            status=ScannerStatus(row["status"]),
                            execution_time_ms=row["execution_time_ms"],
                            severity=row["severity"],
                            confidence=row["confidence"],
                            findings=json.loads(row["findings_json"] or "[]"),
                            evidence=json.loads(row["evidence_json"] or "[]"),
                            raw_output=json.loads(row["raw_output_json"]) if row["raw_output_json"] else None,
                            errors=json.loads(row["errors_json"] or "[]"),
                            detection_count=row["detection_count"],
                            enabled=bool(row["enabled"]),
                        )
                    )
                return results
        except sqlite3.Error as exc:
            logger.error("Failed to load scanner results for report %s: %s", report_id, exc)
            return []

    @staticmethod
    def _scanner_summary_from_results(scanner_results: Sequence[ScannerResult]) -> Dict[str, Any]:
        from collections import Counter

        severity_counts: Counter = Counter()
        status_counts: Counter = Counter()
        finding_count = 0
        for result in scanner_results:
            severity_counts[result.severity] += 1
            status_counts[result.status.value] += 1
            finding_count += int(result.detection_count or 0)
        return {
            "scanner_count": len(scanner_results),
            "status_counts": dict(status_counts),
            "severity_counts": dict(severity_counts),
            "finding_count": finding_count,
        }

    def list_scanner_analytics(self) -> List[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT
                        scanner_name,
                        COUNT(*) AS total_runs,
                        AVG(execution_time_ms) AS average_execution_time_ms,
                        SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS successful_runs,
                        SUM(CASE WHEN status = 'failure' THEN 1 ELSE 0 END) AS failed_runs,
                        SUM(CASE WHEN status = 'unavailable' THEN 1 ELSE 0 END) AS unavailable_runs,
                        SUM(CASE WHEN detection_count > 0 THEN 1 ELSE 0 END) AS detection_runs,
                        MAX(created_at) AS last_execution_time,
                        SUM(detection_count) AS detection_count
                    FROM scanner_results
                    GROUP BY scanner_name
                    ORDER BY total_runs DESC, scanner_name ASC
                    """
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            logger.error("Failed to load scanner analytics: %s", exc)
            return []

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        try:
            with self._connect() as conn:
                total_files = conn.execute("SELECT COUNT(*) AS count FROM file_reports").fetchone()["count"]
                files_today = conn.execute(
                    "SELECT COUNT(*) AS count FROM file_reports WHERE date(analyzed_at) = date('now', 'localtime')"
                ).fetchone()["count"]

                severity_rows = conn.execute(
                    """
                    SELECT COALESCE(risk_severity, 'Low') AS severity, COUNT(*) AS count
                    FROM file_reports
                    GROUP BY COALESCE(risk_severity, 'Low')
                    """
                ).fetchall()
                severity_counts = {row["severity"]: row["count"] for row in severity_rows}

                finding_severity_rows = conn.execute(
                    """
                    SELECT severity, COUNT(*) AS count
                    FROM investigation_findings
                    WHERE status != 'Resolved'
                    GROUP BY severity
                    """
                ).fetchall()
                finding_severity_counts = {row["severity"]: row["count"] for row in finding_severity_rows}

                # System counts
                suspicious_processes = conn.execute(
                    "SELECT COUNT(*) AS c FROM investigation_findings WHERE finding_type = 'suspicious_process' AND status != 'Resolved'"
                ).fetchone()["c"]
                suspicious_services = conn.execute(
                    "SELECT COUNT(*) AS c FROM investigation_findings WHERE finding_type IN ('suspicious_service','service_in_suspicious_path','unsigned_service_binary') AND status != 'Resolved'"
                ).fetchone()["c"]
                persistence_findings = conn.execute(
                    "SELECT COUNT(*) AS c FROM investigation_findings WHERE finding_type = 'persistence_detected' AND status != 'Resolved'"
                ).fetchone()["c"]
                network_findings = conn.execute(
                    "SELECT COUNT(*) AS c FROM investigation_findings WHERE finding_type = 'network_exposure' AND status != 'Resolved'"
                ).fetchone()["c"]

                recent_activity = conn.execute(
                    """
                    SELECT id, analyzed_at, filename, absolute_path, risk_score, risk_severity, sha256
                    FROM file_reports
                    ORDER BY analyzed_at DESC, id DESC
                    LIMIT 10
                    """
                ).fetchall()

                active_threats = conn.execute(
                    """
                    SELECT id, severity, finding_type, description, resource_path,
                           pid, service_name, network_endpoint, first_detected, last_observed, status
                    FROM investigation_findings
                    WHERE status IN ('New', 'Active')
                    ORDER BY
                        CASE severity
                            WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                            WHEN 'Medium' THEN 3 ELSE 4 END,
                        last_observed DESC
                    LIMIT 50
                    """
                ).fetchall()

                return {
                    "total_files": total_files,
                    "files_today": files_today,
                    "severity_counts": severity_counts,
                    "finding_severity_counts": finding_severity_counts,
                    "suspicious_processes": suspicious_processes,
                    "suspicious_services": suspicious_services,
                    "persistence_findings": persistence_findings,
                    "network_findings": network_findings,
                    "recent_activity": [dict(row) for row in recent_activity],
                    "active_threats": [dict(row) for row in active_threats],
                }
        except sqlite3.Error as exc:
            logger.error("Failed to load dashboard metrics: %s", exc)
            return {
                "total_files": 0, "files_today": 0,
                "severity_counts": {}, "finding_severity_counts": {},
                "suspicious_processes": 0, "suspicious_services": 0,
                "persistence_findings": 0, "network_findings": 0,
                "recent_activity": [], "active_threats": [],
            }

    # ------------------------------------------------------------------
    # Watched Folders / Settings
    # ------------------------------------------------------------------

    def list_watched_folders(self) -> List[WatchedFolder]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT id, folder_path, enabled, created_at, updated_at FROM watched_folders ORDER BY created_at ASC, id ASC"
                ).fetchall()
                return [
                    WatchedFolder(
                        id=row["id"],
                        folder_path=row["folder_path"],
                        enabled=bool(row["enabled"]),
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                    )
                    for row in rows
                ]
        except sqlite3.Error as exc:
            logger.error("Failed to list watched folders: %s", exc)
            return []

    def ensure_default_watched_folders(self, folder_paths: Sequence[str]) -> None:
        if self.list_watched_folders():
            return
        self.replace_watched_folders(folder_paths)

    def replace_watched_folders(self, folder_paths: Sequence[str], enabled: bool = True) -> None:
        normalized = []
        for folder_path in folder_paths:
            path_text = str(Path(folder_path).expanduser())
            if path_text not in normalized:
                normalized.append(path_text)

        now = self._utc_now()
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM watched_folders")
                for folder_path in normalized:
                    conn.execute(
                        "INSERT INTO watched_folders (folder_path, enabled, created_at, updated_at) VALUES (?, ?, ?, ?)",
                        (folder_path, int(enabled), now, now),
                    )
        except sqlite3.Error as exc:
            logger.error("Failed to replace watched folders: %s", exc)

    def add_watched_folder(self, folder_path: str, enabled: bool = True) -> None:
        normalized = str(Path(folder_path).expanduser())
        now = self._utc_now()
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO watched_folders (folder_path, enabled, created_at, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(folder_path) DO UPDATE SET
                        enabled = excluded.enabled,
                        updated_at = excluded.updated_at
                    """,
                    (normalized, int(enabled), now, now),
                )
        except sqlite3.Error as exc:
            logger.error("Failed to add watched folder %s: %s", normalized, exc)

    def remove_watched_folder(self, folder_path: str) -> None:
        normalized = str(Path(folder_path).expanduser())
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM watched_folders WHERE folder_path = ?", (normalized,))
        except sqlite3.Error as exc:
            logger.error("Failed to remove watched folder %s: %s", normalized, exc)

    def set_watched_folder_enabled(self, folder_path: str, enabled: bool) -> None:
        normalized = str(Path(folder_path).expanduser())
        now = self._utc_now()
        try:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE watched_folders SET enabled = ?, updated_at = ? WHERE folder_path = ?",
                    (int(enabled), now, normalized),
                )
        except sqlite3.Error as exc:
            logger.error("Failed to update watched folder %s: %s", normalized, exc)

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT setting_value FROM app_settings WHERE setting_key = ?",
                    (key,),
                ).fetchone()
                return row["setting_value"] if row else default
        except sqlite3.Error as exc:
            logger.error("Failed to get setting %s: %s", key, exc)
            return default

    def get_settings(self) -> Dict[str, str]:
        try:
            with self._connect() as conn:
                rows = conn.execute("SELECT setting_key, setting_value FROM app_settings").fetchall()
                return {row["setting_key"]: row["setting_value"] for row in rows}
        except sqlite3.Error as exc:
            logger.error("Failed to load settings: %s", exc)
            return {}

    def set_setting(self, key: str, value: str) -> None:
        now = self._utc_now()
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO app_settings (setting_key, setting_value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(setting_key) DO UPDATE SET
                        setting_value = excluded.setting_value,
                        updated_at = excluded.updated_at
                    """,
                    (key, value, now),
                )
        except sqlite3.Error as exc:
            logger.error("Failed to save setting %s: %s", key, exc)

    def get_scanner_enabled_map(self) -> Dict[str, bool]:
        settings = self.get_settings()
        enabled_map: Dict[str, bool] = {}
        for key, value in settings.items():
            if key.startswith("scanner.enabled."):
                scanner_name = key.replace("scanner.enabled.", "", 1)
                enabled_map[scanner_name] = str(value).strip().lower() in {"1", "true", "yes", "on"}
        return enabled_map

    def set_scanner_enabled(self, scanner_name: str, enabled: bool) -> None:
        self.set_setting(f"scanner.enabled.{scanner_name}", "true" if enabled else "false")

    def ensure_default_scanner_settings(self, defaults: Dict[str, bool]) -> None:
        for scanner_name, enabled in defaults.items():
            key = f"scanner.enabled.{scanner_name}"
            if self.get_setting(key) is None:
                self.set_setting(key, "true" if enabled else "false")

    # ------------------------------------------------------------------
    # Scan history
    # ------------------------------------------------------------------

    def start_scan_history(self, scan_type: str, target_path: str, message: str = "") -> int:
        now = self._utc_now()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scan_history (
                    scan_type, target_path, status, message,
                    report_count, started_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_type, target_path, "running", message, 0, now, None),
            )
            return int(cursor.lastrowid)

    def finish_scan_history(
        self,
        scan_id: int,
        status: str = "completed",
        message: str = "",
        report_count: int = 0,
    ) -> None:
        now = self._utc_now()
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE scan_history
                    SET status = ?, message = ?, report_count = ?, finished_at = ?
                    WHERE id = ?
                    """,
                    (status, message, report_count, now, scan_id),
                )
        except sqlite3.Error as exc:
            logger.error("Failed to finish scan history %s: %s", scan_id, exc)

    def list_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id, scan_type, target_path, status, message,
                           report_count, started_at, finished_at
                    FROM scan_history
                    ORDER BY COALESCE(finished_at, started_at) DESC, id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            logger.error("Failed to list scan history: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Investigation Findings
    # ------------------------------------------------------------------

    def save_finding(self, finding: InvestigationFinding) -> Optional[int]:
        now = self._utc_now()
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO investigation_findings (
                        first_detected, last_observed, file_report_id, scanner,
                        severity, confidence, finding_type, description,
                        evidence_json, resource_type, resource_path,
                        pid, service_name, network_endpoint,
                        relationship_type, is_inference, status, user_acknowledgement
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.first_detected.isoformat(),
                        finding.last_observed.isoformat(),
                        finding.file_report_id,
                        finding.scanner,
                        finding.severity,
                        finding.confidence,
                        finding.finding_type.value,
                        finding.description,
                        json.dumps(finding.evidence),
                        finding.resource_type,
                        finding.resource_path,
                        finding.pid,
                        finding.service_name,
                        finding.network_endpoint,
                        finding.relationship_type.value,
                        int(finding.is_inference),
                        finding.status.value,
                        finding.user_acknowledgement,
                    ),
                )
                return cursor.lastrowid
        except sqlite3.Error as exc:
            logger.error("Failed to save finding: %s", exc)
            return None

    def update_finding_status(self, finding_id: int, status: str, acknowledgement: Optional[str] = None) -> None:
        now = self._utc_now()
        try:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE investigation_findings SET status = ?, last_observed = ?, user_acknowledgement = COALESCE(?, user_acknowledgement) WHERE id = ?",
                    (status, now, acknowledgement, finding_id),
                )
        except sqlite3.Error as exc:
            logger.error("Failed to update finding %s: %s", finding_id, exc)

    def list_findings(self, limit: int = 500, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                where = "WHERE status = ?" if status_filter else ""
                params = ([status_filter] if status_filter else []) + [limit]
                rows = conn.execute(
                    f"""
                    SELECT * FROM investigation_findings
                    {where}
                    ORDER BY
                        CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,
                        last_observed DESC
                    LIMIT ?
                    """,
                    params,
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            logger.error("Failed to list findings: %s", exc)
            return []

    # ------------------------------------------------------------------
    # System Enumeration Snapshots
    # ------------------------------------------------------------------

    def save_processes(self, processes: List[RunningProcess]) -> None:
        now = self._utc_now()
        try:
            with self._connect() as conn:
                # Keep only the last 3 enumeration snapshots to limit DB growth
                conn.execute(
                    "DELETE FROM running_processes WHERE enumerated_at NOT IN (SELECT DISTINCT enumerated_at FROM running_processes ORDER BY enumerated_at DESC LIMIT 2)"
                )
                for p in processes:
                    conn.execute(
                        """
                        INSERT INTO running_processes (
                            pid, name, exe_path, parent_pid, parent_name,
                            username, is_elevated, cmdline, created_time,
                            cpu_percent, memory_mb, connections_json,
                            associated_file_report_id, enumerated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            p.pid, p.name, p.exe_path, p.parent_pid, p.parent_name,
                            p.username,
                            int(p.is_elevated) if p.is_elevated is not None else None,
                            p.cmdline,
                            p.created_time.isoformat() if p.created_time else None,
                            p.cpu_percent, p.memory_mb,
                            json.dumps([c.model_dump() for c in p.connections]),
                            p.associated_file_report_id,
                            p.enumerated_at.isoformat(),
                        ),
                    )
        except sqlite3.Error as exc:
            logger.error("Failed to save processes: %s", exc)

    def list_latest_processes(self) -> List[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                latest = conn.execute(
                    "SELECT MAX(enumerated_at) as ts FROM running_processes"
                ).fetchone()["ts"]
                if not latest:
                    return []
                rows = conn.execute(
                    "SELECT * FROM running_processes WHERE enumerated_at = ? ORDER BY name ASC",
                    (latest,),
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            logger.error("Failed to list processes: %s", exc)
            return []

    def save_services(self, services: List[WindowsService]) -> None:
        now = self._utc_now()
        try:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM windows_services WHERE enumerated_at NOT IN (SELECT DISTINCT enumerated_at FROM windows_services ORDER BY enumerated_at DESC LIMIT 2)"
                )
                for s in services:
                    conn.execute(
                        """
                        INSERT INTO windows_services (
                            service_name, display_name, status, start_type,
                            exe_path, service_account, pid, description,
                            is_system_account, is_autostart, exe_in_suspicious_path,
                            associated_file_report_id, enumerated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            s.service_name, s.display_name, s.status, s.start_type,
                            s.exe_path, s.service_account, s.pid, s.description,
                            int(s.is_system_account), int(s.is_autostart),
                            int(s.exe_in_suspicious_path),
                            s.associated_file_report_id,
                            s.enumerated_at.isoformat(),
                        ),
                    )
        except sqlite3.Error as exc:
            logger.error("Failed to save services: %s", exc)

    def list_latest_services(self) -> List[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                latest = conn.execute(
                    "SELECT MAX(enumerated_at) as ts FROM windows_services"
                ).fetchone()["ts"]
                if not latest:
                    return []
                rows = conn.execute(
                    "SELECT * FROM windows_services WHERE enumerated_at = ? ORDER BY service_name ASC",
                    (latest,),
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            logger.error("Failed to list services: %s", exc)
            return []

    def save_persistence_entries(self, entries: List[PersistenceEntry]) -> None:
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM persistence_entries")
                for e in entries:
                    conn.execute(
                        """
                        INSERT INTO persistence_entries (
                            location, location_path, name, command, exe_path,
                            user_context, privilege, detected_at, associated_file_report_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            e.location.value, e.location_path, e.name,
                            e.command, e.exe_path, e.user_context, e.privilege,
                            e.detected_at.isoformat(), e.associated_file_report_id,
                        ),
                    )
        except sqlite3.Error as exc:
            logger.error("Failed to save persistence entries: %s", exc)

    def list_persistence_entries(self) -> List[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM persistence_entries ORDER BY location ASC, name ASC"
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            logger.error("Failed to list persistence entries: %s", exc)
            return []

    def save_network_exposures(self, exposures: List[NetworkExposure]) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM network_exposures WHERE enumerated_at NOT IN (SELECT DISTINCT enumerated_at FROM network_exposures ORDER BY enumerated_at DESC LIMIT 2)"
                )
                for n in exposures:
                    conn.execute(
                        """
                        INSERT INTO network_exposures (
                            protocol, local_address, local_port, remote_address, remote_port,
                            pid, process_name, exe_path, is_external_facing,
                            associated_file_report_id, enumerated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            n.protocol, n.local_address, n.local_port,
                            n.remote_address, n.remote_port, n.pid, n.process_name,
                            n.exe_path, int(n.is_external_facing),
                            n.associated_file_report_id,
                            n.enumerated_at.isoformat(),
                        ),
                    )
        except sqlite3.Error as exc:
            logger.error("Failed to save network exposures: %s", exc)

    def list_latest_network_exposures(self) -> List[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                latest = conn.execute(
                    "SELECT MAX(enumerated_at) as ts FROM network_exposures"
                ).fetchone()["ts"]
                if not latest:
                    return []
                rows = conn.execute(
                    "SELECT * FROM network_exposures WHERE enumerated_at = ? ORDER BY local_port ASC",
                    (latest,),
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            logger.error("Failed to list network exposures: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Analytics queries
    # ------------------------------------------------------------------

    def get_files_over_time(self, days: int = 30) -> List[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT date(analyzed_at, 'localtime') AS day, COUNT(*) AS count
                    FROM file_reports
                    WHERE analyzed_at >= datetime('now', ?, 'localtime')
                    GROUP BY day ORDER BY day ASC
                    """,
                    (f"-{days} days",),
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            logger.error("Failed to get files over time: %s", exc)
            return []

    def get_findings_over_time(self, days: int = 30) -> List[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT date(first_detected, 'localtime') AS day, COUNT(*) AS count
                    FROM investigation_findings
                    WHERE first_detected >= datetime('now', ?, 'localtime')
                    GROUP BY day ORDER BY day ASC
                    """,
                    (f"-{days} days",),
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            logger.error("Failed to get findings over time: %s", exc)
            return []

    def get_severity_distribution(self) -> Dict[str, int]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT COALESCE(risk_severity, 'Low') AS severity, COUNT(*) AS count FROM file_reports GROUP BY severity"
                ).fetchall()
                return {row["severity"]: row["count"] for row in rows}
        except sqlite3.Error as exc:
            logger.error("Failed to get severity distribution: %s", exc)
            return {}
