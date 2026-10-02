"""
Collects information about running processes using psutil.
"""

from __future__ import annotations

import datetime
from typing import List

import psutil

from app.models.system_models import RunningProcess
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ProcessCollector:
    """Enumerates running processes and their network connections."""

    def collect(self) -> List[RunningProcess]:
        processes: List[RunningProcess] = []
        enumerated_at = datetime.datetime.utcnow()

        for proc in psutil.process_iter(
            attrs=[
                "pid",
                "name",
                "exe",
                "ppid",
                "username",
                "cmdline",
                "create_time",
                "cpu_percent",
                "memory_info",
            ]
        ):
            try:
                info = proc.info
                if info is None:
                    continue

                connections = []
                try:
                    proc_conns = proc.net_connections()
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    proc_conns = []

                if proc_conns:
                    for conn in proc_conns:
                        # psutil connection objects have fd, family, type, laddr, raddr, status
                        # Map to our NetworkConnection model
                        from app.models.system_models import NetworkConnection
                        
                        laddr = conn.laddr
                        raddr = conn.raddr
                        
                        connections.append(
                            NetworkConnection(
                                protocol="TCP" if conn.type == 1 else "UDP" if conn.type == 2 else str(conn.type),
                                local_address=laddr.ip if laddr else "",
                                local_port=laddr.port if laddr else 0,
                                remote_address=raddr.ip if raddr else None,
                                remote_port=raddr.port if raddr else None,
                                state=conn.status,
                            )
                        )

                # Fetch parent name
                parent_name = None
                try:
                    parent = psutil.Process(info["ppid"])
                    parent_name = parent.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError, TypeError):
                    pass
                
                # Check elevation (Windows)
                is_elevated = None
                if info.get("username"):
                    # Basic heuristic: if it's running as SYSTEM, it's elevated
                    if "SYSTEM" in str(info["username"]):
                        is_elevated = True
                        
                create_time = None
                if info.get("create_time"):
                    create_time = datetime.datetime.fromtimestamp(info["create_time"])

                processes.append(
                    RunningProcess(
                        pid=info["pid"],
                        name=info.get("name") or "unknown",
                        exe_path=info.get("exe"),
                        parent_pid=info.get("ppid"),
                        parent_name=parent_name,
                        username=info.get("username"),
                        is_elevated=is_elevated,
                        cmdline=" ".join(info["cmdline"]) if info.get("cmdline") else None,
                        created_time=create_time,
                        cpu_percent=info.get("cpu_percent") or 0.0,
                        memory_mb=(info.get("memory_info").rss / (1024 * 1024)) if info.get("memory_info") else 0.0,
                        connections=connections,
                        enumerated_at=enumerated_at,
                    )
                )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            except Exception as exc:
                logger.debug("Failed to collect process %s: %s", getattr(proc, 'pid', 'unknown'), exc)

        return processes
