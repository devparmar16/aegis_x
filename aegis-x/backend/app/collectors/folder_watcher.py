"""Generic multi-folder download watcher used by the desktop scanner."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Set

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from app.collectors.base_watcher import BaseDownloadWatcher
from app.utils.logger import get_logger

logger = get_logger(__name__)


class _StabilizingEventHandler(FileSystemEventHandler):
    def __init__(
        self,
        ignored_extensions: Set[str],
        stabilize_delay_seconds: float,
        on_stable_file: Callable[[Path], None],
    ) -> None:
        self._ignored_extensions = ignored_extensions
        self._stabilize_delay_seconds = stabilize_delay_seconds
        self._on_stable_file = on_stable_file
        self._pending_paths: Set[str] = set()
        self._lock = threading.Lock()

    def on_created(self, event: FileSystemEvent) -> None:
        self._handle_event(event)

    def on_moved(self, event: FileSystemEvent) -> None:
        if hasattr(event, "dest_path"):
            self._consider_path(Path(event.dest_path), event.is_directory)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._handle_event(event)

    def _handle_event(self, event: FileSystemEvent) -> None:
        self._consider_path(Path(event.src_path), event.is_directory)

    def _consider_path(self, path: Path, is_directory: bool) -> None:
        if is_directory:
            return

        extension = path.suffix.lower().lstrip(".")
        if extension in self._ignored_extensions:
            logger.debug("Ignoring partial/temp download: %s", path)
            return

        with self._lock:
            if str(path) in self._pending_paths:
                return
            self._pending_paths.add(str(path))

        thread = threading.Thread(target=self._wait_for_stability, args=(path,), daemon=True)
        thread.start()

    def _wait_for_stability(self, path: Path) -> None:
        try:
            last_size = -1
            stable_checks = 0
            required_stable_checks = 2

            for _ in range(60):
                if not path.exists():
                    logger.debug("File disappeared before stabilizing: %s", path)
                    return
                try:
                    current_size = path.stat().st_size
                except (OSError, PermissionError):
                    current_size = -1

                if current_size == last_size and current_size >= 0:
                    stable_checks += 1
                else:
                    stable_checks = 0

                last_size = current_size
                if stable_checks >= required_stable_checks:
                    break

                time.sleep(self._stabilize_delay_seconds)

            if not path.exists():
                return

            logger.info("New completed file detected: %s", path)
            self._on_stable_file(path)
        finally:
            with self._lock:
                self._pending_paths.discard(str(path))


class WatchedFolderWatcher(BaseDownloadWatcher):
    """Watches one or more folders for stabilized file completions."""

    def __init__(
        self,
        download_paths: Optional[Iterable[Path]],
        ignored_extensions: List[str],
        stabilize_delay_seconds: float,
        on_new_file: Callable[[Path], None],
        recursive: bool = False,
    ) -> None:
        super().__init__(on_new_file)
        self._download_paths: List[Path] = list(download_paths or [])
        self._recursive = recursive
        self._observer = Observer()
        self._handler = _StabilizingEventHandler(
            ignored_extensions=set(ignored_extensions),
            stabilize_delay_seconds=stabilize_delay_seconds,
            on_stable_file=on_new_file,
        )
        self._running = False

    def set_download_paths(self, download_paths: Iterable[Path]) -> None:
        self._download_paths = list(download_paths)

    def start(self) -> None:
        valid_paths = []
        for path in self._download_paths:
            if path.exists():
                valid_paths.append(path)
            else:
                logger.warning("Skipping missing watched folder: %s", path)

        if not valid_paths:
            raise FileNotFoundError("No watched folders exist or were configured")

        if self._running:
            self.stop()

        for path in valid_paths:
            self._observer.schedule(self._handler, str(path), recursive=self._recursive)

        self._observer.start()
        self._running = True
        logger.info("Watching %d folder(s) for downloads (recursive=%s)", len(valid_paths), self._recursive)

    def stop(self) -> None:
        if not self._running:
            return
        self._observer.stop()
        self._observer.join(timeout=5)
        self._observer = Observer()
        self._running = False
        logger.info("Stopped watching folders")