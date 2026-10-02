"""
Watches Google Chrome's Downloads folder for newly-completed downloads.

Design notes:
- Chrome writes in-progress downloads as `<name>.crdownload`, then renames
  to the final filename once complete. We ignore partial extensions
  entirely and only react to the final, renamed file.
- Even after the rename, Chrome (or antivirus scanning) may briefly hold
  a lock or continue writing. We debounce by polling the file size until
  it stabilizes for `stabilize_delay_seconds` before firing the callback,
  which also naturally handles "locked file" / "permission denied"
  races without crashing.
- This class only knows about Chrome's folder + naming conventions. All
  analysis logic lives elsewhere, per the project's modularity
  requirement — adding a FirefoxWatcher later means implementing this
  same BaseDownloadWatcher contract, nothing more.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable, List, Set

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from app.collectors.base_watcher import BaseDownloadWatcher
from app.utils.logger import get_logger

logger = get_logger(__name__)


class _StabilizingEventHandler(FileSystemEventHandler):
    """Watchdog event handler that debounces file-creation events until
    the file has stopped growing/changing, then hands off to a callback.
    """

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
        # Chrome renames <file>.crdownload -> <file> on completion, which
        # watchdog reports as a "moved" event with dest_path == final name.
        if hasattr(event, "dest_path"):
            self._consider_path(Path(event.dest_path), event.is_directory)

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

        thread = threading.Thread(
            target=self._wait_for_stability, args=(path,), daemon=True
        )
        thread.start()

    def _wait_for_stability(self, path: Path) -> None:
        try:
            last_size = -1
            stable_checks = 0
            required_stable_checks = 2

            # Poll until the file size hasn't changed across consecutive
            # checks, guarding against reacting to a file still being
            # written. Bounded to avoid waiting forever on a stuck file.
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

            logger.info("New completed download detected: %s", path)
            self._on_stable_file(path)
        finally:
            with self._lock:
                self._pending_paths.discard(str(path))


class ChromeDownloadWatcher(BaseDownloadWatcher):
    """Watches the configured Chrome Downloads folder for new files."""

    def __init__(
        self,
        download_path: Path,
        ignored_extensions: List[str],
        stabilize_delay_seconds: float,
        on_new_file: Callable[[Path], None],
    ) -> None:
        super().__init__(on_new_file)
        self._download_path = download_path
        self._observer = Observer()
        self._handler = _StabilizingEventHandler(
            ignored_extensions=set(ignored_extensions),
            stabilize_delay_seconds=stabilize_delay_seconds,
            on_stable_file=on_new_file,
        )

    def start(self) -> None:
        if not self._download_path.exists():
            logger.error(
                "Chrome download path does not exist: %s. "
                "Watcher will not start.",
                self._download_path,
            )
            raise FileNotFoundError(
                f"CHROME_DOWNLOAD_PATH does not exist: {self._download_path}"
            )

        self._observer.schedule(
            self._handler, str(self._download_path), recursive=False
        )
        self._observer.start()
        logger.info("Watching Chrome downloads folder: %s", self._download_path)

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=5)
        logger.info("Stopped watching Chrome downloads folder")
