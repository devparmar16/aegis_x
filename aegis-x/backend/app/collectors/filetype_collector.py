"""
Content-based file type detection (magic bytes).

Uses python-magic to sniff the actual file format and compares it
against the file extension. A mismatch (e.g. photo.jpg that is actually
a PE executable) is a strong indicator of malicious intent.
"""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Optional

try:
    import magic
    _MAGIC_AVAILABLE = True
except ImportError:
    _MAGIC_AVAILABLE = False

from app.collectors.base_collector import BaseCollector
from app.models.file_report import FileTypeInfo
from app.utils.logger import get_logger

logger = get_logger(__name__)


class FileTypeCollector(BaseCollector):
    """Detects actual file format via magic bytes and compares to extension."""

    def __init__(self) -> None:
        if not _MAGIC_AVAILABLE:
            logger.warning("python-magic not installed; file type detection will degrade.")

    def collect(self, file_path: Path) -> Optional[FileTypeInfo]:
        if not file_path.exists():
            return None

        extension = file_path.suffix.lower().lstrip(".")
        
        # 1. Extension-based MIME
        detected_mime = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"

        # 2. Magic bytes hex (first 8 bytes)
        magic_bytes_hex = ""
        try:
            with open(file_path, "rb") as f:
                magic_bytes_hex = f.read(8).hex().upper()
        except Exception as exc:
            logger.error("Failed to read magic bytes for %s: %s", file_path, exc)

        # 3. Actual format via python-magic
        actual_format = "unknown"
        if _MAGIC_AVAILABLE:
            try:
                # Get descriptive type (e.g. "PE32 executable (GUI) Intel 80386")
                actual_format = magic.from_file(str(file_path))
            except Exception as exc:
                logger.error("python-magic failed for %s: %s", file_path, exc)
                actual_format = "error"
        else:
            actual_format = "unavailable"

        # 4. Mismatch logic
        mismatch = False
        mismatch_desc = None
        detected_type = "unknown"

        # Check for obvious executables masquerading as other things
        if actual_format != "unavailable" and actual_format != "error":
            if "executable" in actual_format.lower() or "pe32" in actual_format.lower():
                detected_type = "executable"
                # Executable masquerading as non-executable
                if extension not in {"exe", "dll", "sys", "scr", "com", "msi", "bat", "cmd", "ps1", "vbs"}:
                    mismatch = True
                    mismatch_desc = f"File has extension .{extension} but content is a PE Executable"
            elif "zip archive" in actual_format.lower():
                detected_type = "archive"
            elif "pdf document" in actual_format.lower():
                detected_type = "document"
                if extension not in {"pdf"}:
                    mismatch = True
                    mismatch_desc = f"File has extension .{extension} but content is a PDF Document"

        # Fallback to hex signature for PE mismatch if magic unavailable
        if not _MAGIC_AVAILABLE or actual_format == "error":
            if magic_bytes_hex.startswith("4D5A"): # MZ
                detected_type = "executable"
                if extension not in {"exe", "dll", "sys", "scr", "com", "msi", "bat", "cmd", "ps1", "vbs"}:
                    mismatch = True
                    mismatch_desc = f"File has extension .{extension} but starts with MZ header (Executable)"

        return FileTypeInfo(
            extension=extension,
            detected_mime=detected_mime,
            detected_type=detected_type,
            magic_bytes_hex=magic_bytes_hex,
            actual_format=actual_format,
            mismatch=mismatch,
            mismatch_description=mismatch_desc,
        )
