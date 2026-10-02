"""Desktop entry point for Aegis-X."""

from __future__ import annotations

import logging
import queue
import signal
import sys
import tkinter as tk
from pathlib import Path
from typing import Optional

from app.config.config import ConfigurationError, get_config
from app.database.db_manager import DatabaseManager
from app.services.scan_service import ScanService
from app.services.system_service import SystemService
from app.ui.dashboard_app import AegisXDashboardApp
from app.utils.logger import get_logger

logger = get_logger(__name__)


class AegisXApplication:
    """Top-level desktop application that wires the UI and scan service."""

    def __init__(self) -> None:
        self._config = get_config()
        self._db = DatabaseManager(self._config.database_path)
        self._service = ScanService(self._config, self._db)
        self._system_service = SystemService(self._config, self._db)
        self._ui: Optional[AegisXDashboardApp] = None
        self._shutdown_event = False

    def run(self) -> None:
        logger.info("Starting Aegis-X desktop application")
        logger.info("Scan folders: %s", self._config.scan_folders)

        self._service.start()
        self._system_service.start()
        try:
            self._ui = AegisXDashboardApp(self._config, self._db, self._service, self._system_service)
        except tk.TclError as exc:
            logger.warning(
                "No desktop display available (%s); running headless scanner only.",
                exc,
            )
            self._run_headless()
            return

        signal.signal(signal.SIGINT, self._handle_sigint)
        try:
            self._ui.mainloop()
        finally:
            self.shutdown()

    def _run_headless(self) -> None:
        signal.signal(signal.SIGINT, self._handle_sigint)
        try:
            while not self._shutdown_event:
                try:
                    event = self._service.events.get(timeout=0.5)
                except queue.Empty:
                    continue
                if event.get("type") == "report_saved":
                    report = event.get("report")
                    logger.info(
                        "Report saved (headless): %s severity=%s score=%.0f [id=%s]",
                        report.metadata.filename,
                        report.risk.severity.value if report and report.risk else "unknown",
                        report.risk.score if report and report.risk else 0.0,
                        report.report_id if report else None,
                    )
                elif event.get("type") == "error":
                    logger.error("%s", event.get("message"))
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        if self._shutdown_event:
            return
        self._shutdown_event = True
        logger.info("Shutting down Aegis-X")
        self._service.stop()
        self._system_service.stop()

    def _handle_sigint(self, signum, frame) -> None:  # noqa: ANN001
        logger.info("Received interrupt signal")
        if self._ui is not None:
            self._ui.quit()
        self._shutdown_event = True


def main() -> None:
    try:
        app = AegisXApplication()
    except ConfigurationError as exc:
        print(f"[Aegis-X] Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    logging.getLogger().setLevel(logging.INFO)
    app.run()


if __name__ == "__main__":
    main()
