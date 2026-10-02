"""
Abstract download-folder watcher interface.

Today only Chrome is implemented, but the project requirement is that
additional browsers can be added later without touching analysis, risk,
AI, database, or UI code. Any new watcher just needs to call the same
`on_new_file` callback with a completed file path.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable


class BaseDownloadWatcher(ABC):
    """Abstract base for a browser-specific download folder watcher."""

    def __init__(self, on_new_file: Callable[[Path], None]) -> None:
        """`on_new_file` is invoked with the absolute path of a file only
        once it has finished downloading and stabilized.
        """
        self._on_new_file = on_new_file

    @abstractmethod
    def start(self) -> None:
        """Begin watching. Must not block the calling thread."""
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        """Stop watching and release any resources."""
        raise NotImplementedError
