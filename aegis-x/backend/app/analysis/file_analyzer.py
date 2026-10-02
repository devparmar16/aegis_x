"""
Analysis orchestration layer.

`FileAnalyzer` is the single place that knows how to turn a file path
into a complete `FileReport` by running each independent collector and
assembling the results. It deliberately has no knowledge of *how* the
file was discovered (watchdog, a manual scan, a future browser module,
etc.) — it only needs a path. This keeps monitoring and analysis
decoupled, per the project's extensibility requirement.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from app.collectors.file_info_collector import FileInfoCollector
from app.collectors.hash_collector import HashCollector
from app.collectors.pe_collector import PECollector
from app.collectors.signature_collector import SignatureCollector
from app.collectors.filetype_collector import FileTypeCollector
from app.models.file_report import FileReport, SignatureInfo, SignatureStatus
from app.utils.logger import get_logger

logger = get_logger(__name__)


class FileAnalyzer:
    """Orchestrates independent collectors to build a FileReport."""

    def __init__(
        self,
        file_info_collector: Optional[FileInfoCollector] = None,
        hash_collector: Optional[HashCollector] = None,
        pe_collector: Optional[PECollector] = None,
        signature_collector: Optional[SignatureCollector] = None,
        filetype_collector: Optional[FileTypeCollector] = None,
    ) -> None:
        # Dependency injection with sane defaults — callers (e.g. tests)
        # can swap in mocks without touching this class's logic.
        self._file_info_collector = file_info_collector or FileInfoCollector()
        self._hash_collector = hash_collector or HashCollector()
        self._pe_collector = pe_collector or PECollector()
        self._signature_collector = signature_collector or SignatureCollector()
        self._filetype_collector = filetype_collector or FileTypeCollector()

    def analyze(self, file_path: Path) -> Optional[FileReport]:
        """Run all collectors for the given file and return a FileReport.

        Returns None only if core metadata collection fails outright
        (e.g. the file vanished or is completely inaccessible) — every
        other collector failure degrades gracefully instead of aborting
        the whole analysis.
        """
        logger.info("Starting analysis for: %s", file_path)

        metadata = self._file_info_collector.collect(file_path)
        if metadata is None:
            logger.error("Core metadata collection failed for %s; aborting analysis", file_path)
            return None

        hashes = self._hash_collector.collect(file_path)
        if hashes is None:
            logger.warning("Hashing failed for %s; continuing with empty hashes", file_path)
            from app.models.file_report import HashInfo
            hashes = HashInfo(sha256="", sha1="", md5="")
            
        file_type_info = self._filetype_collector.collect(file_path)

        try:
            signature = self._signature_collector.collect(file_path)
        except Exception as exc:
            logger.error("Signature collection raised for %s: %s", file_path, exc)
            signature = SignatureInfo(status=SignatureStatus.UNKNOWN, detail=str(exc))

        pe_info = None
        # Use FileTypeCollector's insight if available; fallback to extension
        is_exe = metadata.is_executable
        if file_type_info and file_type_info.detected_type == "executable":
            is_exe = True
            
        if is_exe:
            try:
                pe_info = self._pe_collector.collect(file_path)
            except Exception as exc:
                logger.error("PE collection raised for %s: %s", file_path, exc)

        report = FileReport(
            metadata=metadata,
            hashes=hashes,
            signature=signature,
            pe_info=pe_info,
            file_type_info=file_type_info,
        )

        logger.info(
            "Analysis complete for %s (executable=%s, pe=%s)",
            file_path,
            is_exe,
            pe_info is not None,
        )
        return report
