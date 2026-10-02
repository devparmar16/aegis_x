"""
Correlates system-level evidence to generate investigation findings.
"""

from __future__ import annotations

import datetime
from typing import List, Optional

from app.database.db_manager import DatabaseManager
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


class CorrelationService:
    """Analyzes system snapshots for suspicious activities and relationships."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    def correlate_system_snapshot(
        self,
        processes: List[RunningProcess],
        services: List[WindowsService],
        persistence_entries: List[PersistenceEntry],
        network_exposures: List[NetworkExposure],
    ) -> List[InvestigationFinding]:
        """Correlate a point-in-time snapshot of the system."""
        
        new_findings: List[InvestigationFinding] = []
        now = datetime.datetime.utcnow()
        
        # 1. Analyze Processes
        for proc in processes:
            # Rule: Executable running from a suspicious location
            if proc.exe_path:
                lower_path = proc.exe_path.lower()
                if "appdata\\local\\temp" in lower_path or "programdata" in lower_path:
                    if "docker" not in lower_path and "slack" not in lower_path:
                        finding = InvestigationFinding(
                            first_detected=now,
                            last_observed=now,
                            scanner="CorrelationEngine",
                            severity="Medium",
                            confidence=0.7,
                            finding_type=FindingType.SUSPICIOUS_PROCESS,
                            description=f"Process '{proc.name}' running from unusual path: {proc.exe_path}",
                            evidence=[f"pid={proc.pid}", f"cmdline={proc.cmdline}", f"path={proc.exe_path}"],
                            resource_type="process",
                            resource_path=proc.exe_path,
                            pid=proc.pid,
                            relationship_type=RelationshipType.EXECUTED_FROM,
                        )
                        new_findings.append(finding)

            # Rule: Process listening on an external port
            for conn in proc.connections:
                if conn.status == "LISTEN" and conn.local_address in {"0.0.0.0", "::"}:
                    if proc.name.lower() not in {"svchost.exe", "system", "spoolsv.exe"}:
                        finding = InvestigationFinding(
                            first_detected=now,
                            last_observed=now,
                            scanner="CorrelationEngine",
                            severity="Medium",
                            confidence=0.8,
                            finding_type=FindingType.NETWORK_EXPOSURE,
                            description=f"Process '{proc.name}' listening on all interfaces (Port {conn.local_port})",
                            evidence=[f"pid={proc.pid}", f"port={conn.local_port}", f"protocol={conn.protocol}"],
                            resource_type="process",
                            resource_path=proc.exe_path,
                            pid=proc.pid,
                            network_endpoint=f"{conn.protocol}:{conn.local_port}",
                            relationship_type=RelationshipType.LISTENING_ON,
                        )
                        new_findings.append(finding)

        # 2. Analyze Services
        for srv in services:
            if srv.exe_in_suspicious_path:
                finding = InvestigationFinding(
                    first_detected=now,
                    last_observed=now,
                    scanner="CorrelationEngine",
                    severity="High",
                    confidence=0.9,
                    finding_type=FindingType.SERVICE_IN_SUSPICIOUS_PATH,
                    description=f"Service '{srv.service_name}' binary located in suspicious path.",
                    evidence=[f"exe_path={srv.exe_path}", f"start_type={srv.start_type}"],
                    resource_type="service",
                    resource_path=srv.exe_path,
                    pid=srv.pid,
                    service_name=srv.service_name,
                    relationship_type=RelationshipType.INSTALLED_AS,
                )
                new_findings.append(finding)

        # 3. Analyze Persistence
        for entry in persistence_entries:
            if entry.exe_path:
                lower_path = entry.exe_path.lower()
                if "appdata" in lower_path or "temp" in lower_path or "programdata" in lower_path:
                    if "onedrive.exe" not in lower_path and "teams.exe" not in lower_path:
                        finding = InvestigationFinding(
                            first_detected=now,
                            last_observed=now,
                            scanner="CorrelationEngine",
                            severity="High",
                            confidence=0.8,
                            finding_type=FindingType.PERSISTENCE_DETECTED,
                            description=f"Suspicious persistence entry '{entry.name}' at {entry.location.value}",
                            evidence=[f"command={entry.command}", f"location={entry.location_path}"],
                            resource_type="registry_key" if entry.location in {PersistenceLocation.REGISTRY_RUN, PersistenceLocation.REGISTRY_RUN_ONCE, PersistenceLocation.REGISTRY_RUN_USER} else "file",
                            resource_path=entry.exe_path,
                            relationship_type=RelationshipType.PERSISTENCE_ENTRY,
                        )
                        new_findings.append(finding)

        # Deduplicate and save findings
        self._merge_and_save_findings(new_findings)

        return new_findings

    def _merge_and_save_findings(self, new_findings: List[InvestigationFinding]) -> None:
        """Merge new findings with existing ones in the database to avoid duplicates."""
        try:
            existing_active = self._db.list_findings(limit=1000, status_filter=FindingStatus.NEW.value)
            existing_active.extend(self._db.list_findings(limit=1000, status_filter=FindingStatus.ACTIVE.value))
        except Exception:
            existing_active = []

        def make_key(f: InvestigationFinding | dict) -> str:
            if isinstance(f, dict):
                return f"{f.get('finding_type', '')}:{f.get('resource_path', '')}:{f.get('pid', '')}:{f.get('service_name', '')}"
            return f"{f.finding_type.value}:{f.resource_path}:{f.pid or ''}:{f.service_name or ''}"

        existing_keys = {make_key(f): f["id"] for f in existing_active if isinstance(f, dict)}

        for finding in new_findings:
            key = make_key(finding)
            if key in existing_keys:
                try:
                    self._db.update_finding_status(existing_keys[key], FindingStatus.ACTIVE.value)
                except Exception:
                    pass
            else:
                try:
                    self._db.save_finding(finding)
                except Exception as exc:
                    logger.error("Failed to save finding: %s", exc)

