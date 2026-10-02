"""Background scan orchestration for the desktop dashboard."""

from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from app.ai.ai_factory import create_ai_provider
from app.analysis.file_analyzer import FileAnalyzer
from app.collectors.folder_watcher import WatchedFolderWatcher
from app.config.config import AppConfig
from app.database.db_manager import DatabaseManager
from app.models.file_report import FileReport
from app.risk.risk_engine import RiskEngine
from app.scanners.engine import ScannerEngine
from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class _QueuedFile:
    file_path: Path
    source: str


class ScanService:
    """Owns watcher state, background processing, and UI event delivery."""

    def __init__(self, base_config: AppConfig, database: DatabaseManager) -> None:
        self._base_config = base_config
        self._db = database
        self._shutdown_event = threading.Event()
        self._pending_files: "queue.Queue[_QueuedFile]" = queue.Queue()
        self._events: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="AegisX-ScanWorker",
        )

        self._watched_folders = self._load_initial_folders()
        self._realtime_enabled = self._load_realtime_enabled()
        self._effective_config = self._resolve_runtime_config()
        self._analyzer = FileAnalyzer()
        self._risk_engine = RiskEngine()
        self._scanner_engine = ScannerEngine(self._effective_config, self._db)
        self._ai_provider = create_ai_provider(self._effective_config)
        self._watcher = WatchedFolderWatcher(
            download_paths=self._watched_folders,
            ignored_extensions=self._effective_config.ignored_extensions,
            stabilize_delay_seconds=self._effective_config.file_stabilize_delay_seconds,
            on_new_file=self._enqueue_realtime_file,
            recursive=self._effective_config.scan_recursive,
        )

    @property
    def events(self) -> "queue.Queue[Dict[str, Any]]":
        return self._events

    @property
    def watched_folders(self) -> List[Path]:
        return list(self._watched_folders)

    @property
    def realtime_enabled(self) -> bool:
        return self._realtime_enabled

    @property
    def effective_config(self) -> AppConfig:
        return self._effective_config

    def start(self) -> None:
        if not self._worker_thread.is_alive():
            self._worker_thread.start()
        self._apply_realtime_state()

    def stop(self) -> None:
        self._shutdown_event.set()
        try:
            self._watcher.stop()
        except Exception as exc:
            logger.error("Failed to stop folder watcher: %s", exc)

    def reload_runtime_settings(self) -> None:
        """Reload AI/logging runtime overrides saved in the database."""
        self._effective_config = self._resolve_runtime_config()
        self._ai_provider = create_ai_provider(self._effective_config)
        self._scanner_engine = ScannerEngine(self._effective_config, self._db)
        logging.getLogger().setLevel(getattr(logging, self._effective_config.log_level, logging.INFO))
        self._events.put({"type": "settings_reloaded"})

    def refresh_watched_folders(self) -> None:
        self._watched_folders = self._load_initial_folders()
        self._watcher.set_download_paths(self._watched_folders)
        self._db.set_setting("default_scan_folders", self._format_folder_setting(str(path) for path in self._watched_folders))
        self._apply_realtime_state()
        self._events.put({"type": "folders_changed"})

    def set_realtime_monitoring(self, enabled: bool) -> None:
        self._realtime_enabled = enabled
        self._db.set_setting("realtime_monitoring_enabled", "true" if enabled else "false")
        self._apply_realtime_state()
        self._events.put({"type": "realtime_changed", "enabled": enabled})

    def set_watched_folders(self, folder_paths: Iterable[str]) -> None:
        self._db.replace_watched_folders(folder_paths)
        self.refresh_watched_folders()

    def add_watched_folder(self, folder_path: str) -> None:
        self._db.add_watched_folder(folder_path)
        self.refresh_watched_folders()

    def remove_watched_folder(self, folder_path: str) -> None:
        self._db.remove_watched_folder(folder_path)
        self.refresh_watched_folders()

    def scan_now(self, folder_paths: Optional[Iterable[str]] = None) -> None:
        folders = [Path(folder) for folder in (folder_paths or [str(path) for path in self._watched_folders])]
        if not folders:
            self._events.put({"type": "warning", "message": "No watched folders configured"})
            return
        threading.Thread(target=self._scan_folders_task, args=(folders,), daemon=True, name="AegisX-ManualScan").start()

    def _load_initial_folders(self) -> List[Path]:
        watched = self._db.list_watched_folders()
        if watched:
            return [Path(folder.folder_path) for folder in watched if folder.enabled]

        default_folders = [str(path) for path in self._base_config.scan_folders]
        if not default_folders:
            # Fallback if config is completely empty
            default_folders = [str(Path.home() / "Downloads")]

        self._db.ensure_default_watched_folders(default_folders)
        self._db.set_setting("default_scan_folders", self._format_folder_setting(default_folders))
        return [Path(folder) for folder in default_folders]

    def _load_realtime_enabled(self) -> bool:
        value = self._db.get_setting("realtime_monitoring_enabled", "true") or "true"
        return value.strip().lower() in {"1", "true", "yes", "on"}

    def _resolve_runtime_config(self) -> AppConfig:
        from dataclasses import replace

        settings = self._db.get_settings()
        ai_provider = settings.get("ai_provider", self._base_config.ai_provider)
        model_name = settings.get("model_name", self._base_config.model_name)
        timeout_raw = settings.get("ai_request_timeout_seconds", str(self._base_config.ai_request_timeout_seconds))
        log_level = settings.get("log_level", self._base_config.log_level)

        try:
            timeout = int(timeout_raw)
        except ValueError:
            timeout = self._base_config.ai_request_timeout_seconds

        return replace(
            self._base_config,
            ai_provider=ai_provider,
            model_name=model_name,
            ai_request_timeout_seconds=timeout,
            log_level=log_level,
        )

    @staticmethod
    def _format_folder_setting(folder_paths: Iterable[str]) -> str:
        return "\n".join(str(Path(path).expanduser()) for path in folder_paths)

    def _apply_realtime_state(self) -> None:
        if self._realtime_enabled:
            self._watcher.set_download_paths(self._watched_folders)
            try:
                self._watcher.start()
            except FileNotFoundError as exc:
                self._events.put({"type": "error", "message": str(exc)})
        else:
            try:
                self._watcher.stop()
            except Exception as exc:
                logger.error("Failed to stop realtime watcher: %s", exc)

    def _enqueue_realtime_file(self, file_path: Path) -> None:
        self._pending_files.put(_QueuedFile(file_path=file_path, source="realtime"))

    def _scan_folders_task(self, folders: List[Path]) -> None:
        for folder in folders:
            if not folder.exists():
                self._events.put({"type": "warning", "message": f"Missing folder: {folder}"})
                continue

            scan_id = self._db.start_scan_history("manual", str(folder), "Manual scan started")
            queued = 0
            try:
                for file_path in folder.rglob("*"):
                    if file_path.is_file():
                        queued += 1
                        self._pending_files.put(_QueuedFile(file_path=file_path, source="manual"))
                self._db.finish_scan_history(scan_id, status="queued", message="Files queued for analysis", report_count=queued)
                self._events.put({"type": "scan_complete", "folder": str(folder), "count": queued})
            except Exception as exc:
                logger.error("Manual scan failed for %s: %s", folder, exc)
                self._db.finish_scan_history(scan_id, status="failed", message=str(exc), report_count=queued)
                self._events.put({"type": "error", "message": f"Scan failed for {folder}: {exc}"})

    def _worker_loop(self) -> None:
        while not self._shutdown_event.is_set():
            try:
                item = self._pending_files.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                self._process_file(item)
            except Exception as exc:
                logger.error("Unhandled error processing %s: %s", item.file_path, exc)
                self._events.put({"type": "error", "message": f"Failed to process {item.file_path}: {exc}"})

    def _process_file(self, item: _QueuedFile) -> None:
        report = self._analyzer.analyze(item.file_path)
        if report is None:
            logger.warning("Skipping %s: analysis produced no report", item.file_path)
            return

        scanner_results, scanner_summary = self._scanner_engine.scan(report)
        report.scanner_results = scanner_results
        report.scanner_summary = scanner_summary

        report.risk = self._risk_engine.score(report)

        try:
            report.ai_explanation = self._ai_provider.analyze(report)
        except Exception as exc:
            logger.error("AI provider failed for %s: %s", item.file_path, exc)

        report_id = self._db.save_report(report)
        if report_id is not None:
            report.report_id = report_id
            self._db.save_scanner_results(report_id, report)

        self._events.put(
            {
                "type": "report_saved",
                "report_id": report.report_id,
                "report": report,
                "source": item.source,
                "scanner_count": len(scanner_results),
            }
        )
