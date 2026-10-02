"""
Collects PE (Portable Executable) header evidence for Windows executables,
DLLs, and drivers using `pefile`.

This collector only activates on files that parse as valid PE images.
For non-PE files, `collect()` returns None and the caller simply omits
`pe_info` from the report.
"""

from __future__ import annotations

import math
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from app.collectors.base_collector import BaseCollector
from app.models.file_report import PEHeaderInfo, PESectionInfo
from app.utils.logger import get_logger

logger = get_logger(__name__)

# DLL characteristics flags (IMAGE_OPTIONAL_HEADER.DllCharacteristics)
_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040  # ASLR
_IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100     # DEP/NX
_IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000      # Control Flow Guard

# Characteristics flags (IMAGE_FILE_HEADER.Characteristics)
_IMAGE_FILE_DLL = 0x2000

# Subsystem values relevant to executable "type"
_SUBSYSTEM_NAMES = {
    1: "NATIVE (driver)",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
}

# A conservative, evidence-only watchlist of imports that are commonly
# associated with process injection, credential access, or evasion.
# This is NOT a verdict — it only feeds the deterministic risk engine
# as one weighted factor among many.
_SUSPICIOUS_IMPORT_WATCHLIST = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "SetWindowsHookEx", "NtUnmapViewOfSection", "VirtualProtect",
    "LoadLibraryA", "GetProcAddress", "IsDebuggerPresent",
    "CryptEncrypt", "InternetOpenA", "URLDownloadToFileA",
    "WinExec", "ShellExecuteA", "AdjustTokenPrivileges",
}


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte array."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    for count in occurrences:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return entropy


class PECollector(BaseCollector):
    """Extracts PE header security-relevant evidence via pefile."""

    def collect(self, file_path: Path) -> Optional[PEHeaderInfo]:
        try:
            import pefile
        except ImportError:
            logger.warning("pefile is not installed; skipping PE analysis")
            return None

        try:
            pe = pefile.PE(str(file_path), fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                ]
            )
        except pefile.PEFormatError:
            # Not a PE file at all — expected for the majority of downloads.
            return None
        except Exception as exc:
            logger.error("Unexpected error parsing PE file %s: %s", file_path, exc)
            return None

        try:
            info = self._extract(pe)
        finally:
            pe.close()

        return info

    def _extract(self, pe: "pefile.PE") -> PEHeaderInfo:
        import pefile

        characteristics = pe.FILE_HEADER.Characteristics
        dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
        
        entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) if hasattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint') else None
        image_base = hex(pe.OPTIONAL_HEADER.ImageBase) if hasattr(pe.OPTIONAL_HEADER, 'ImageBase') else None
        
        subsystem_val = pe.OPTIONAL_HEADER.Subsystem
        subsystem_name = _SUBSYSTEM_NAMES.get(subsystem_val, f"SUBSYSTEM_{subsystem_val}")

        is_dll = bool(characteristics & _IMAGE_FILE_DLL)
        machine = pe.FILE_HEADER.Machine
        architecture = {
            0x014C: "x86",
            0x8664: "x64",
            0xAA64: "ARM64",
            0x01C0: "ARM",
        }.get(machine, hex(machine))

        aslr_enabled = bool(dll_characteristics & _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        dep_enabled = bool(dll_characteristics & _IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        cfg_enabled = bool(dll_characteristics & _IMAGE_DLLCHARACTERISTICS_GUARD_CF)

        try:
            timestamp = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
        except (OSError, OverflowError, ValueError):
            timestamp = None

        sections: List[PESectionInfo] = []
        section_names: List[str] = []
        section_entropy: Dict[str, float] = {}
        suspicious_sections: List[str] = []
        
        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip("\x00")
            section_names.append(name)
            
            entropy = _calculate_entropy(section.get_data())
            section_entropy[name] = entropy
            
            # Executable + writable sections are a classic packing/injection
            # indicator (self-modifying code).
            is_exec = bool(section.Characteristics & 0x20000000)
            is_write = bool(section.Characteristics & 0x80000000)
            is_suspicious = False
            
            if is_exec and is_write:
                suspicious_sections.append(name)
                is_suspicious = True
                
            # Non-standard section names can indicate a custom packer.
            if name and name not in {
                ".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata",
                ".idata", ".edata", ".bss", ".tls",
            }:
                if name not in suspicious_sections:
                    suspicious_sections.append(name)
                    is_suspicious = True

            sections.append(
                PESectionInfo(
                    name=name,
                    virtual_address=hex(section.VirtualAddress),
                    raw_size=section.SizeOfRawData,
                    entropy=entropy,
                    is_executable=is_exec,
                    is_writable=is_write,
                    is_suspicious=is_suspicious
                )
            )

        imports: List[str] = []
        suspicious_imports: List[str] = []
        dll_dependencies: List[str] = []
        
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll:
                    dll_name = entry.dll.decode(errors="ignore")
                    dll_dependencies.append(dll_name)
                    
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode(errors="ignore")
                        imports.append(name)
                        if name in _SUSPICIOUS_IMPORT_WATCHLIST:
                            suspicious_imports.append(name)

        exports: List[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if symbol.name:
                    exports.append(symbol.name.decode(errors="ignore"))

        compiler_hint = self._guess_compiler(pe)

        is_driver = subsystem_val == 1
        executable_type = subsystem_name
        if is_dll:
            executable_type = f"DLL ({executable_type})"

        return PEHeaderInfo(
            architecture=architecture,
            is_dll=is_dll,
            is_driver=is_driver,
            timestamp=timestamp,
            entry_point=entry_point,
            image_base=image_base,
            subsystem=subsystem_name,
            subsystem_value=subsystem_val,
            pe_characteristics=characteristics,
            aslr_enabled=aslr_enabled,
            dep_nx_enabled=dep_enabled,
            cfg_enabled=cfg_enabled,
            sections=sections,
            section_names=section_names,
            section_entropy=section_entropy,
            suspicious_sections=suspicious_sections,
            imports=imports,
            exports=exports,
            dll_dependencies=dll_dependencies,
            suspicious_imports=suspicious_imports,
            compiler_hint=compiler_hint,
            executable_type=executable_type,
        )

    @staticmethod
    def _guess_compiler(pe: "pefile.PE") -> Optional[str]:
        """Best-effort compiler/linker hint from the linker version fields."""
        try:
            major = pe.OPTIONAL_HEADER.MajorLinkerVersion
            minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
            return f"Linker v{major}.{minor}"
        except AttributeError:
            return None
