"""
Inspects archive containers (ZIP, RAR, 7z, TAR, GZ, MSI, CAB) without fully 
unpacking them to disk. Recursively extracts metadata about contained files.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from app.models.file_report import ArchiveInfo, ArchiveEntry
from app.models.scanner_result import ScannerResult, ScannerStatus
from app.scanners.base import BaseScanner, ScannerContext
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Extensions considered archives
_ARCHIVE_EXTENSIONS = {"zip", "jar", "msi", "rar", "7z", "tar", "gz", "bz2", "xz", "cab"}
_MAX_DEPTH = 3
_MAX_ENTRIES = 5000


@dataclass
class _ArchiveStats:
    total_entries: int = 0
    nested_archives: int = 0
    executables: int = 0
    encrypted: bool = False
    depth: int = 0
    entries: List[ArchiveEntry] = None

    def __post_init__(self):
        if self.entries is None:
            self.entries = []


class ArchiveScanner(BaseScanner):
    """Deep inspection of archive contents."""

    scanner_name = "archive"
    description = "Deep structural archive inspection"
    default_enabled = True

    def scan(self, context: ScannerContext) -> ScannerResult:
        metadata = context.report.metadata
        ext = metadata.extension.lower() if metadata.extension else ""
        
        # Fast path rejection
        if ext not in _ARCHIVE_EXTENSIONS and not zipfile.is_zipfile(context.file_path):
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.SKIPPED,
                severity="Low",
                confidence=0.0,
                evidence=["Not recognized as an archive file"],
            )

        stats = _ArchiveStats()
        try:
            self._inspect_file(context.file_path, stats)
        except zipfile.BadZipFile:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.WARNING,
                severity="Low",
                confidence=0.3,
                evidence=["Appears to be a corrupt or invalid ZIP file"],
                errors=["BadZipFile"],
            )
        except Exception as exc:
            logger.error("Failed to inspect archive %s: %s", context.file_path, exc)
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScannerStatus.FAILURE,
                severity="Low",
                confidence=0.0,
                evidence=["Error reading archive structure"],
                errors=[str(exc)],
            )
            
        context.report.archive_info = ArchiveInfo(
            is_archive=True,
            encrypted=stats.encrypted,
            total_entries=stats.total_entries,
            nested_archives=stats.nested_archives,
            executables_inside=stats.executables,
            entries=stats.entries,
            max_depth_reached=stats.depth,
        )

        evidence = [f"Contains {stats.total_entries} files (depth {stats.depth})"]
        findings = []
        severity = "Low"
        confidence = 0.8
        detection_count = 0

        if stats.encrypted:
            severity = "Medium"
            detection_count += 1
            findings.append("ENCRYPTED_ARCHIVE")
            evidence.append("Archive is encrypted/password-protected")
            
        if stats.executables > 0:
            severity = "Medium" if severity == "Low" else severity
            detection_count += 1
            findings.append("EXECUTABLES_IN_ARCHIVE")
            evidence.append(f"Contains {stats.executables} executable files")

        if stats.nested_archives > 1:
            severity = "Medium" if severity == "Low" else severity
            detection_count += 1
            findings.append("NESTED_ARCHIVES")
            evidence.append(f"Contains {stats.nested_archives} nested archives")

        return ScannerResult(
            scanner_name=self.scanner_name,
            status=ScannerStatus.SUCCESS,
            severity=severity,
            confidence=confidence,
            findings=findings,
            evidence=evidence,
            raw_output={"stats": {"total": stats.total_entries, "executables": stats.executables, "encrypted": stats.encrypted}},
            detection_count=detection_count,
        )

    def _inspect_file(self, file_path: Path, stats: _ArchiveStats) -> None:
        """Inspect a file on disk."""
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zf:
                self._inspect_zip(zf, stats, current_depth=1)
        elif tarfile.is_tarfile(file_path):
            with tarfile.open(file_path, 'r') as tf:
                self._inspect_tar(tf, stats, current_depth=1)
        # TODO: Add RAR and 7z support via subprocess or specialized libs if required

    def _inspect_zip(self, zf: zipfile.ZipFile, stats: _ArchiveStats, current_depth: int) -> None:
        stats.depth = max(stats.depth, current_depth)
        
        for info in zf.infolist():
            if stats.total_entries >= _MAX_ENTRIES:
                break
                
            if info.is_dir():
                continue
                
            stats.total_entries += 1
            
            # Check encryption
            is_encrypted = info.flag_bits & 0x1 != 0
            if is_encrypted:
                stats.encrypted = True
                
            path = Path(info.filename)
            ext = path.suffix.lower().lstrip('.')
            
            is_exe = ext in {'exe', 'dll', 'scr', 'vbs', 'ps1', 'bat', 'cmd', 'msi', 'js', 'com', 'hta'}
            is_archive = ext in _ARCHIVE_EXTENSIONS
            
            if is_exe:
                stats.executables += 1
            if is_archive:
                stats.nested_archives += 1
                
            if len(stats.entries) < 100:  # Cap the saved entries for the report
                stats.entries.append(ArchiveEntry(
                    path=info.filename,
                    size_bytes=info.file_size,
                    is_executable=is_exe,
                    encrypted=is_encrypted
                ))

            # Recursion for nested ZIPs (only if not encrypted and within depth)
            if is_archive and not is_encrypted and current_depth < _MAX_DEPTH:
                try:
                    # Only recursively parse zip files for now to avoid memory explosion
                    if ext in {'zip', 'jar', 'apk'}:
                        with zf.open(info) as nested_file:
                            nested_bytes = nested_file.read(min(info.file_size, 1024 * 1024 * 50)) # Max 50MB in-memory extraction
                            nested_zf = zipfile.ZipFile(io.BytesIO(nested_bytes))
                            self._inspect_zip(nested_zf, stats, current_depth + 1)
                except Exception as exc:
                    logger.debug("Failed to inspect nested archive %s: %s", info.filename, exc)

    def _inspect_tar(self, tf: tarfile.TarFile, stats: _ArchiveStats, current_depth: int) -> None:
        stats.depth = max(stats.depth, current_depth)
        
        for info in tf.getmembers():
            if stats.total_entries >= _MAX_ENTRIES:
                break
                
            if not info.isfile():
                continue
                
            stats.total_entries += 1
            path = Path(info.name)
            ext = path.suffix.lower().lstrip('.')
            
            is_exe = ext in {'exe', 'dll', 'scr', 'vbs', 'ps1', 'bat', 'cmd', 'msi', 'js', 'com', 'hta'}
            is_archive = ext in _ARCHIVE_EXTENSIONS
            
            if is_exe:
                stats.executables += 1
            if is_archive:
                stats.nested_archives += 1
                
            if len(stats.entries) < 100:
                stats.entries.append(ArchiveEntry(
                    path=info.name,
                    size_bytes=info.size,
                    is_executable=is_exe,
                    encrypted=False # TAR itself doesn't support file-level encryption the way ZIP does
                ))
