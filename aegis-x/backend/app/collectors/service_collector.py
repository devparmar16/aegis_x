"""
Collects information about Windows services using psutil (and winreg if needed).
"""

from __future__ import annotations

import datetime
from typing import List

import psutil

from app.models.system_models import WindowsService
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ServiceCollector:
    """Enumerates Windows services."""

    def collect(self) -> List[WindowsService]:
        services: List[WindowsService] = []
        enumerated_at = datetime.datetime.utcnow()
        
        # psutil.win_service_iter() is available on Windows
        if not hasattr(psutil, "win_service_iter"):
            logger.warning("Windows services enumeration not available on this platform")
            return services

        for srv in psutil.win_service_iter():
            try:
                name = srv.name()
                display_name = srv.display_name()
                status = srv.status()
                start_type = srv.start_type()
                try:
                    exe_path = srv.binpath()
                except Exception:
                    exe_path = ""
                try:
                    pid = srv.pid()
                except Exception:
                    pid = None

                # Check for suspicious paths
                is_suspicious_path = False
                if exe_path:
                    lower_path = exe_path.lower()
                    if "appdata" in lower_path or "temp" in lower_path or "programdata" in lower_path:
                        is_suspicious_path = True

                is_autostart = (start_type == "automatic")

                services.append(
                    WindowsService(
                        service_name=name or "unknown",
                        display_name=display_name or "",
                        status=status or "unknown",
                        start_type=start_type or "unknown",
                        exe_path=exe_path or "",
                        service_account="",
                        pid=pid,
                        description="",
                        is_system_account=False,
                        is_autostart=is_autostart,
                        exe_in_suspicious_path=is_suspicious_path,
                        enumerated_at=enumerated_at,
                    )
                )

            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied:
                pass
            except Exception as exc:
                logger.debug("Failed to collect service info for %s: %s", getattr(srv, 'name', lambda: 'unknown')(), exc)

        return services
