"""
Collects system-wide network exposures (listening ports).
"""

from __future__ import annotations

import datetime
from typing import List

import psutil

from app.models.system_models import NetworkExposure
from app.utils.logger import get_logger

logger = get_logger(__name__)


class NetworkCollector:
    """Enumerates system-wide listening ports."""

    def collect(self) -> List[NetworkExposure]:
        exposures: List[NetworkExposure] = []
        enumerated_at = datetime.datetime.utcnow()

        try:
            # psutil.net_connections(kind="inet") was deprecated/removed or restricted in newer psutil versions.
            if hasattr(psutil, "net_connections"):
                connections = psutil.net_connections(kind="inet")
            else:
                connections = []
                for p in psutil.process_iter(['pid', 'name']):
                    try:
                        connections.extend(p.net_connections(kind="inet"))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except psutil.AccessDenied:
            logger.warning("Access denied when trying to get system-wide network connections. Run as Administrator.")
            return exposures
        except Exception as exc:
            logger.error("Failed to enumerate network connections: %s", exc)
            return exposures

        # Cache process names and exe paths
        proc_info_cache = {}

        for conn in connections:
            if conn.status != "LISTEN":
                continue

            laddr = conn.laddr
            if not laddr:
                continue

            pid = conn.pid
            process_name = None
            exe_path = None

            if pid is not None:
                if pid not in proc_info_cache:
                    try:
                        p = psutil.Process(pid)
                        proc_info_cache[pid] = (p.name(), p.exe())
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_info_cache[pid] = (None, None)
                
                process_name, exe_path = proc_info_cache[pid]

            is_external_facing = False
            if laddr.ip == "0.0.0.0" or laddr.ip == "::":
                is_external_facing = True

            exposures.append(
                NetworkExposure(
                    protocol="TCP" if conn.type == 1 else "UDP" if conn.type == 2 else str(conn.type),
                    local_address=laddr.ip,
                    local_port=laddr.port,
                    remote_address=None,
                    remote_port=None,
                    pid=pid,
                    process_name=process_name or "unknown",
                    exe_path=exe_path,
                    is_external_facing=is_external_facing,
                    enumerated_at=enumerated_at,
                )
            )

        return exposures
