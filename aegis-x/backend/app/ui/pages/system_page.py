"""
System Page.
"""

from __future__ import annotations

import tkinter as tk
from typing import List, Optional

import customtkinter as ctk
from tkinter import messagebox, ttk

from app.database.db_manager import DatabaseManager


class SystemPage(ctk.CTkFrame):
    def __init__(self, master: tk.Misc, db: DatabaseManager, system_service) -> None:
        super().__init__(master, fg_color="transparent")
        self._db = db
        self._system_service = system_service
        self._build_ui()

    def _build_ui(self) -> None:
        top = ctk.CTkFrame(self, corner_radius=18)
        top.pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(top, text="System Exposure", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(top, text="View active processes, services, persistence mechanisms, and network connections.", text_color="#9a9ba5").pack(anchor="w", padx=18, pady=(0, 16))

        controls = ctk.CTkFrame(self, corner_radius=16)
        controls.pack(fill="x", padx=12, pady=(0, 8))
        ctk.CTkButton(controls, text="Trigger System Scan", command=self._trigger_scan).pack(side="left", padx=10, pady=12)
        ctk.CTkButton(controls, text="Refresh View", command=self.refresh).pack(side="right", padx=10, pady=12)

        body = ctk.CTkFrame(self, corner_radius=16)
        body.pack(fill="both", expand=True, padx=12, pady=8)

        self._tabs = ctk.CTkTabview(body)
        self._tabs.pack(fill="both", expand=True, padx=12, pady=12)
        
        self._tab_processes = self._tabs.add("Processes")
        self._tab_services = self._tabs.add("Services")
        self._tab_network = self._tabs.add("Network")
        self._tab_persistence = self._tabs.add("Persistence")

        self._tree_processes = self._build_tree(self._tab_processes, [("pid", "PID", 80), ("name", "Name", 200), ("exe", "Executable", 400), ("user", "User", 150)])
        self._tree_services = self._build_tree(self._tab_services, [("name", "Name", 200), ("display_name", "Display Name", 250), ("status", "Status", 100), ("start_type", "Start Type", 100), ("bin_path", "Binary Path", 400)])
        self._tree_network = self._build_tree(self._tab_network, [("pid", "PID", 80), ("type", "Type", 80), ("laddr", "Local Address", 200), ("raddr", "Remote Address", 200), ("status", "Status", 120)])
        self._tree_persistence = self._build_tree(self._tab_persistence, [("type", "Type", 150), ("name", "Name", 200), ("path", "Path", 400), ("target", "Target", 400)])

        self.refresh()

    def _build_tree(self, parent, columns: list) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=[col[0] for col in columns], show="headings", height=15)
        for col, title, width in columns:
            tree.heading(col, text=title)
            tree.column(col, width=width, anchor="w")
        tree.pack(fill="both", expand=True, padx=8, pady=8)
        return tree

    def refresh(self) -> None:
        self._tree_processes.delete(*self._tree_processes.get_children())
        self._tree_services.delete(*self._tree_services.get_children())
        self._tree_network.delete(*self._tree_network.get_children())
        self._tree_persistence.delete(*self._tree_persistence.get_children())

        snapshot = self._system_service.get_last_snapshot()
        if not snapshot:
            return

        for proc in snapshot.get("processes", []):
            self._tree_processes.insert("", "end", values=(
                proc.pid,
                proc.name,
                proc.exe_path or "",
                proc.username or "",
            ))

        for svc in snapshot.get("services", []):
            self._tree_services.insert("", "end", values=(
                svc.service_name,
                svc.display_name,
                svc.status,
                svc.start_type,
                svc.exe_path or "",
            ))

        for conn in snapshot.get("network", []):
            remote = f"{conn.remote_address}:{conn.remote_port}" if conn.remote_address else ""
            self._tree_network.insert("", "end", values=(
                conn.pid or "",
                conn.protocol,
                f"{conn.local_address}:{conn.local_port}",
                remote,
                "",
            ))

        for item in snapshot.get("persistence", []):
            self._tree_persistence.insert("", "end", values=(
                item.location.value,
                item.name,
                item.location_path,
                item.exe_path or "",
            ))

    def _trigger_scan(self) -> None:
        self._system_service.scan_now()
        messagebox.showinfo("Aegis-X", "System scan triggered. The view will update once complete.")
