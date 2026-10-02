"""
Collects digital signature status and publisher information for a file.

On Windows, this uses the WinVerifyTrust API (via ctypes) to check
Authenticode signature validity, and falls back to parsing the
certificate table via pefile for the publisher name when full
verification isn't possible. On non-Windows platforms (e.g. during
development/testing), this collector degrades gracefully to
SignatureStatus.UNKNOWN rather than failing.
"""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Optional

from app.collectors.base_collector import BaseCollector
from app.models.file_report import SignatureInfo, SignatureStatus
from app.utils.logger import get_logger

logger = get_logger(__name__)


class SignatureCollector(BaseCollector):
    """Determines whether a file is digitally signed and by whom."""

    def collect(self, file_path: Path) -> SignatureInfo:
        # Check if it's actually an executable based on extension first
        extension = file_path.suffix.lower().lstrip('.')
        if extension not in {'exe', 'dll', 'sys', 'scr', 'msi', 'com'}:
            return SignatureInfo(
                status=SignatureStatus.NOT_APPLICABLE, 
                detail="File is not a PE executable"
            )

        if platform.system() != "Windows":
            return self._collect_publisher_only(file_path)

        try:
            return self._collect_windows(file_path)
        except Exception as exc:
            logger.error("Signature verification failed for %s: %s", file_path, exc)
            return SignatureInfo(status=SignatureStatus.UNKNOWN, detail=str(exc))

    def _collect_windows(self, file_path: Path) -> SignatureInfo:
        """Verify Authenticode signature using WinVerifyTrust."""
        import ctypes
        from ctypes import wintypes

        WINTRUST_ACTION_GENERIC_VERIFY_V2 = (
            "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"
        )

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", ctypes.c_wchar_p),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p),
            ]

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_byte * 8),
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", ctypes.c_wchar_p),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
            ]

        def _guid_from_string(guid_str: str) -> GUID:
            import uuid

            u = uuid.UUID(guid_str)
            data4 = (ctypes.c_byte * 8)(*u.bytes[8:])
            return GUID(
                u.time_low, u.time_mid, u.time_hi_version, data4
            )

        file_info = WINTRUST_FILE_INFO(
            cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO),
            pcwszFilePath=str(file_path),
            hFile=None,
            pgKnownSubject=None,
        )

        trust_data = WINTRUST_DATA(
            cbStruct=ctypes.sizeof(WINTRUST_DATA),
            pPolicyCallbackData=None,
            pSIPClientData=None,
            dwUIChoice=2,  # WTD_UI_NONE
            fdwRevocationChecks=0,  # WTD_REVOKE_NONE
            dwUnionChoice=1,  # WTD_CHOICE_FILE
            pFile=ctypes.pointer(file_info),
            dwStateAction=0,  # WTD_STATEACTION_IGNORE
            hWVTStateData=None,
            pwszURLReference=None,
            dwProvFlags=0x00000010,  # WTD_CACHE_ONLY_URL_RETRIEVAL
            dwUIContext=0,
        )

        guid = _guid_from_string(WINTRUST_ACTION_GENERIC_VERIFY_V2)
        wintrust = ctypes.WinDLL("wintrust.dll")
        result = wintrust.WinVerifyTrust(
            None, ctypes.byref(guid), ctypes.byref(trust_data)
        )

        publisher = self._extract_publisher_via_pefile(file_path)

        if result == 0:
            return SignatureInfo(
                status=SignatureStatus.SIGNED_VALID,
                publisher=publisher,
                detail="WinVerifyTrust: trusted",
            )
        elif publisher:
            return SignatureInfo(
                status=SignatureStatus.SIGNED_INVALID,
                publisher=publisher,
                detail=f"WinVerifyTrust returned code {result}",
            )
        else:
            return SignatureInfo(
                status=SignatureStatus.UNSIGNED,
                publisher=None,
                detail=f"WinVerifyTrust returned code {result}",
            )

    def _collect_publisher_only(self, file_path: Path) -> SignatureInfo:
        """Non-Windows fallback: attempt to read publisher from the
        certificate table without cryptographic verification.
        """
        publisher = self._extract_publisher_via_pefile(file_path)
        if publisher:
            return SignatureInfo(
                status=SignatureStatus.UNKNOWN,
                publisher=publisher,
                detail="Signature presence detected; validity not verified "
                       "(non-Windows host)",
            )
        return SignatureInfo(
            status=SignatureStatus.UNKNOWN,
            detail="Signature verification unavailable on this platform",
        )

    @staticmethod
    def _extract_publisher_via_pefile(file_path: Path) -> Optional[str]:
        """Best-effort publisher extraction from the PE certificate table.

        Full X.509 parsing is out of scope for the MVP; this looks for a
        readable organization-name string within the embedded certificate
        blob, which is sufficient as supporting evidence (not a trust
        decision) for the risk engine and UI.
        """
        try:
            import pefile
            import re

            pe = pefile.PE(str(file_path), fast_load=True)
            try:
                security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
                ]
                if security_dir.VirtualAddress == 0 or security_dir.Size == 0:
                    return None

                cert_data = pe.write()[
                    security_dir.VirtualAddress
                    + 8 : security_dir.VirtualAddress
                    + security_dir.Size
                ]
                match = re.search(rb"O=([^,\x00]{2,80})", cert_data)
                if match:
                    return match.group(1).decode(errors="ignore").strip()
                return None
            finally:
                pe.close()
        except Exception:
            return None
