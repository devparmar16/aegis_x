"""
Collects basic filesystem-level metadata about a downloaded file:
name, extension, size, timestamps, MIME type, Shannon entropy, and
whether the file appears to be an executable format.
"""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

from app.collectors.base_collector import BaseCollector
from app.models.file_report import FileMetadata
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Magic bytes that indicate common executable / package formats.
# Used as a MIME-detection fallback when python-magic is unavailable.
_EXECUTABLE_SIGNATURES = {
    b"MZ": "application/x-msdownload",       # PE (EXE/DLL/SYS)
    b"\x7fELF": "application/x-elf",         # Linux ELF
    b"PK\x03\x04": "application/zip",        # ZIP-based (could be msi, jar, docx, etc.)
}

_EXECUTABLE_EXTENSIONS = {
    "exe", "dll", "sys", "scr", "com", "msi", "bat", "cmd", "ps1",
    "vbs", "js", "jar", "cpl", "gadget", "hta",
}


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy (bits per byte) of the given data.

    High entropy (close to 8.0) often indicates encryption, compression,
    or packing — one of the risk engine's evidence factors.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _detect_mime_type(file_path: Path, sample: bytes) -> str:
    """Detect MIME type, preferring python-magic when available and
    falling back to signature sniffing, then to mimetypes/extension.
    """
    try:
        import magic  # python-magic

        return magic.from_file(str(file_path), mime=True)
    except Exception as exc:  # pragma: no cover - environment dependent
        logger.debug("python-magic unavailable or failed (%s); falling back", exc)

    for signature, mime in _EXECUTABLE_SIGNATURES.items():
        if sample.startswith(signature):
            return mime

    import mimetypes

    guessed, _ = mimetypes.guess_type(str(file_path))
    return guessed or "application/octet-stream"


class FileInfoCollector(BaseCollector):
    """Collects core filesystem metadata for a file."""

    def __init__(self, entropy_sample_size: int = 1024 * 1024) -> None:
        # Cap how much of large files we read for entropy to keep this fast.
        self._entropy_sample_size = entropy_sample_size

    def collect(self, file_path: Path) -> Optional[FileMetadata]:
        try:
            stat_result = file_path.stat()
        except (OSError, PermissionError) as exc:
            logger.error("Could not stat file %s: %s", file_path, exc)
            return None

        try:
            with open(file_path, "rb") as handle:
                sample = handle.read(self._entropy_sample_size)
        except (OSError, PermissionError) as exc:
            logger.error("Could not read file %s for entropy/mime: %s", file_path, exc)
            sample = b""

        extension = file_path.suffix.lower().lstrip(".")
        mime_type = _detect_mime_type(file_path, sample)
        entropy = _shannon_entropy(sample)
        is_executable = (
            extension in _EXECUTABLE_EXTENSIONS
            or sample.startswith(b"MZ")
            or "executable" in mime_type
        )

        return FileMetadata(
            filename=file_path.name,
            extension=extension,
            absolute_path=str(file_path.resolve()),
            size_bytes=stat_result.st_size,
            created_time=datetime.fromtimestamp(stat_result.st_ctime),
            modified_time=datetime.fromtimestamp(stat_result.st_mtime),
            mime_type=mime_type,
            entropy=entropy,
            is_executable=is_executable,
        )
