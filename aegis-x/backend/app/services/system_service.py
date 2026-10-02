"""
Orchestrates system-wide enumeration and delegates to the correlation service.
"""

from __future__ import annotations

import datetime
import threading
import time
from typing import Optional

from app.collectors.network_collector import NetworkCollector
from app.collectors.persistence_collector import PersistenceCollector
from app.collectors.process_collector import ProcessCollector
from app.collectors.service_collector import ServiceCollector
from app.config.config import AppConfig
from app.database.db_manager import DatabaseManager
from app.services.correlation_service import CorrelationService
from app.utils.logger import get_logger

logger = get_logger(__name__)


class SystemService:
    """Manages periodic collection of system exposure data and correlation."""

    def __init__(self, config: AppConfig, database: DatabaseManager) -> None:
        self._config = config
        self._db = database
        self._correlation_service = CorrelationService(database)
        
        self._process_collector = ProcessCollector()
        self._service_collector = ServiceCollector()
        self._persistence_collector = PersistenceCollector()
        self._network_collector = NetworkCollector()
        
        self._shutdown_event = threading.Event()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="AegisX-SystemWorker",
        )
        self._last_scan_time: Optional[datetime.datetime] = None
        self._last_snapshot: Optional[dict] = None

    def get_last_snapshot(self) -> Optional[dict]:
        """Return the latest enumerated system snapshot."""
        return self._last_snapshot

    def start(self) -> None:
        if not self._worker_thread.is_alive():
            self._worker_thread.start()

    def stop(self) -> None:
        self._shutdown_event.set()

    def scan_now(self) -> None:
        """Trigger a manual system scan immediately."""
        threading.Thread(target=self._run_scan, daemon=True, name="AegisX-ManualSystemScan").start()

    def _worker_loop(self) -> None:
        logger.info("System background scanning worker initialized (automatic timer disabled; manual scan available).")
        while not self._shutdown_event.is_set():
            time.sleep(1)

    def _run_scan(self) -> None:
        logger.debug("Starting system enumeration scan")
        now = datetime.datetime.utcnow()
        
        try:
            # 1. Collect
            processes = self._process_collector.collect()
            services = self._service_collector.collect()
            persistences = self._persistence_collector.collect()
            networks = self._network_collector.collect()
            
            # 2. Save Snapshots
            self._db.save_processes(processes)
            self._db.save_services(services)
            self._db.save_persistence_entries(persistences)
            self._db.save_network_exposures(networks)
            
            self._last_snapshot = {
                "processes": processes,
                "services": services,
                "persistence": persistences,
                "network": networks,
            }
            
            # 3. Record the run
            with self._db._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO system_scan_runs (
                        started_at, finished_at, process_count, service_count, 
                        persistence_count, network_count, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        now.isoformat(),
                        datetime.datetime.utcnow().isoformat(),
                        len(processes),
                        len(services),
                        len(persistences),
                        len(networks),
                        "completed"
                    )
                )
            
            # 4. Correlate
            findings = self._correlation_service.correlate_system_snapshot(
                processes=processes,
                services=services,
                persistence_entries=persistences,
                network_exposures=networks
            )
            
            if findings:
                logger.info("System scan completed. Found %s suspicious indicators.", len(findings))
            else:
                logger.debug("System scan completed. No new suspicious indicators found.")
                
        except Exception as exc:
            logger.error("System scan failed: %s", exc)
            with self._db._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO system_scan_runs (
                        started_at, finished_at, status, error
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (now.isoformat(), datetime.datetime.utcnow().isoformat(), "failed", str(exc))
                )
