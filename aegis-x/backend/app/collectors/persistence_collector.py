"""
Collects persistence mechanisms such as Registry Run keys and Startup folder contents.
"""

from __future__ import annotations

import datetime
import os
import platform
import winreg
from pathlib import Path
from typing import List

from app.models.system_models import PersistenceEntry, PersistenceLocation
from app.utils.logger import get_logger

logger = get_logger(__name__)


class PersistenceCollector:
    """Enumerates common Windows persistence locations."""

    def collect(self) -> List[PersistenceEntry]:
        entries: List[PersistenceEntry] = []
        if platform.system() != "Windows":
            logger.warning("Persistence enumeration not available on this platform")
            return entries

        detected_at = datetime.datetime.utcnow()

        # 1. Registry Run Keys
        run_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", PersistenceLocation.REGISTRY_RUN, "SYSTEM"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceLocation.REGISTRY_RUN_ONCE, "SYSTEM"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", PersistenceLocation.REGISTRY_RUN_USER, "USER"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceLocation.REGISTRY_RUN_USER, "USER"),
        ]

        for hkey, subkey, loc, context in run_keys:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            exe_path = self._extract_exe_path(str(value))
                            entries.append(
                                PersistenceEntry(
                                    location=loc,
                                    location_path=f"{'HKLM' if hkey == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}\\{subkey}",
                                    name=name,
                                    command=str(value),
                                    exe_path=exe_path,
                                    user_context=context,
                                    privilege="High" if hkey == winreg.HKEY_LOCAL_MACHINE else "Medium",
                                    detected_at=detected_at,
                                )
                            )
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                pass
            except Exception as exc:
                logger.debug("Failed to read registry key %s: %s", subkey, exc)

        # 2. Startup Folders
        startup_folders = [
            (os.environ.get("APPDATA", "") + r"\Microsoft\Windows\Start Menu\Programs\Startup", "USER"),
            (os.environ.get("PROGRAMDATA", "") + r"\Microsoft\Windows\Start Menu\Programs\Startup", "SYSTEM"),
        ]

        for folder, context in startup_folders:
            if not folder:
                continue
                
            folder_path = Path(folder)
            if not folder_path.exists():
                continue

            try:
                for child in folder_path.iterdir():
                    if child.is_file() and child.name != "desktop.ini":
                        entries.append(
                            PersistenceEntry(
                                location=PersistenceLocation.STARTUP_FOLDER,
                                location_path=str(folder_path),
                                name=child.name,
                                command=str(child),
                                exe_path=str(child),
                                user_context=context,
                                privilege="High" if context == "SYSTEM" else "Medium",
                                detected_at=detected_at,
                            )
                        )
            except Exception as exc:
                logger.debug("Failed to read startup folder %s: %s", folder, exc)

        # TODO: Add Scheduled Tasks (schtasks /query /fo csv)
        # TODO: Add WMI event subscriptions

        return entries

    @staticmethod
    def _extract_exe_path(command: str) -> str:
        """Simple heuristic to extract the executable path from a command line."""
        if not command:
            return ""
        
        # If it's quoted, extract the quoted part
        if command.startswith('"'):
            end_quote = command.find('"', 1)
            if end_quote != -1:
                return command[1:end_quote]
                
        # Otherwise, take the first space-separated token (flawed but works for most basic paths without spaces)
        return command.split(" ", 1)[0]
