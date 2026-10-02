"""
Browser Scanner page.
"""

from __future__ import annotations

import tkinter as tk
from typing import Optional

import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk

from app.database.db_manager import DatabaseManager
from app.services.scan_service import ScanService


class BrowserScannerPage(ctk.CTkFrame):
    def __init__(self, master: tk.Misc, db: DatabaseManager, service: ScanService, refresh_reports_callback) -> None:
        super().__init__(master, fg_color="transparent")
        self._db = db
        self._service = service
        self._refresh_reports_callback = refresh_reports_callback
        self._selected_folder: Optional[str] = None
        self._watcher_var = tk.BooleanVar(value=service.realtime_enabled)
        self._build_ui()

    def _build_ui(self) -> None:
        top = ctk.CTkFrame(self, corner_radius=18)
        top.pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(top, text="Browser Scanner", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(top, text="Manage watched folders, trigger manual scans, and control realtime monitoring.", text_color="#9a9ba5").pack(anchor="w", padx=18, pady=(0, 16))

        controls = ctk.CTkFrame(self, corner_radius=16)
        controls.pack(fill="x", padx=12, pady=(0, 8))
        ctk.CTkButton(controls, text="Browse Folder", command=self._browse_folder).pack(side="left", padx=10, pady=12)
        ctk.CTkButton(controls, text="Add Folder", command=self._add_folder).pack(side="left", padx=10, pady=12)
        ctk.CTkButton(controls, text="Remove Folder", command=self._remove_folder).pack(side="left", padx=10, pady=12)
        ctk.CTkButton(controls, text="Scan Now", command=self._scan_now).pack(side="left", padx=10, pady=12)
        ctk.CTkCheckBox(controls, text="Enable Realtime Monitoring", variable=self._watcher_var, command=self._toggle_monitoring).pack(side="right", padx=18, pady=12)

        body = ctk.CTkFrame(self, corner_radius=16)
        body.pack(fill="both", expand=True, padx=12, pady=8)

        left = ctk.CTkFrame(body, corner_radius=16)
        left.pack(side="left", fill="both", expand=True, padx=(12, 8), pady=12)
        ctk.CTkLabel(left, text="Watched Folders", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(14, 8))
        self._folders_tree = ttk.Treeview(left, columns=("folder", "enabled", "updated"), show="headings", height=14)
        for column, title, width in [("folder", "Folder", 480), ("enabled", "Enabled", 100), ("updated", "Updated", 160)]:
            self._folders_tree.heading(column, text=title)
            self._folders_tree.column(column, width=width, anchor="w")
        self._folders_tree.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._folders_tree.bind("<<TreeviewSelect>>", self._on_folder_select)

        right = ctk.CTkFrame(body, corner_radius=16)
        right.pack(side="left", fill="both", expand=True, padx=(8, 12), pady=12)
        ctk.CTkLabel(right, text="Folder Status", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(14, 8))
        self._status_text = ctk.CTkTextbox(right, height=260)
        self._status_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self.refresh()

    def refresh(self) -> None:
        self._folders_tree.delete(*self._folders_tree.get_children())
        folders = self._db.list_watched_folders()
        for folder in folders:
            self._folders_tree.insert("", "end", iid=str(folder.id), values=(folder.folder_path, "Yes" if folder.enabled else "No", folder.updated_at))
        self._status_text.delete("1.0", "end")
        self._status_text.insert("end", f"Realtime monitoring: {'enabled' if self._service.realtime_enabled else 'disabled'}\n")
        self._status_text.insert("end", f"Watched folders: {len(folders)}\n")
        for folder in folders:
            self._status_text.insert("end", f"- {folder.folder_path}\n")
        self._watcher_var.set(self._service.realtime_enabled)

    def _selected_values(self) -> Optional[tuple[str, str, str]]:
        selection = self._folders_tree.selection()
        if not selection:
            return None
        values = self._folders_tree.item(selection[0], "values")
        if len(values) < 3:
            return None
        return values[0], values[1], values[2]

    def _on_folder_select(self, event=None) -> None:  # noqa: ANN001
        values = self._selected_values()
        self._selected_folder = values[0] if values else None

    def _browse_folder(self) -> None:
        folder = filedialog.askdirectory()
        if folder:
            self._db.add_watched_folder(folder)
            self._service.refresh_watched_folders()
            self.refresh()

    def _add_folder(self) -> None:
        self._browse_folder()

    def _remove_folder(self) -> None:
        if not self._selected_folder:
            messagebox.showinfo("Aegis-X", "Select a watched folder first.")
            return
        self._db.remove_watched_folder(self._selected_folder)
        self._service.refresh_watched_folders()
        self.refresh()

    def _scan_now(self) -> None:
        self._service.scan_now()
        self._refresh_reports_callback()
        messagebox.showinfo("Aegis-X", "Manual scan queued for watched folders.")

    def _toggle_monitoring(self) -> None:
        self._service.set_realtime_monitoring(bool(self._watcher_var.get()))
        self.refresh()
