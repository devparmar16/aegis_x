"""
Collects cryptographic hashes (SHA256, MD5) for a file.

Hashing is streamed in fixed-size chunks so large files don't get loaded
into memory at once, and any read failure (locked file, permission
denied) is caught and logged rather than propagated.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

from app.collectors.base_collector import BaseCollector
from app.models.file_report import HashInfo
from app.utils.logger import get_logger

logger = get_logger(__name__)

_CHUNK_SIZE = 1024 * 1024  # 1 MB


class HashCollector(BaseCollector):
    """Computes SHA256, SHA1, and MD5 digests for a file."""

    def collect(self, file_path: Path) -> Optional[HashInfo]:
        sha256_hash = hashlib.sha256()
        sha1_hash = hashlib.sha1()
        md5_hash = hashlib.md5()

        try:
            with open(file_path, "rb") as handle:
                while True:
                    chunk = handle.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
                    sha1_hash.update(chunk)
                    md5_hash.update(chunk)
        except (OSError, PermissionError) as exc:
            logger.error("Failed to hash file %s: %s", file_path, exc)
            return None

        return HashInfo(
            sha256=sha256_hash.hexdigest(),
            sha1=sha1_hash.hexdigest(),
            md5=md5_hash.hexdigest()
        )
