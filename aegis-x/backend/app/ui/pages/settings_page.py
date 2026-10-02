"""
Settings page.
"""

from __future__ import annotations

import tkinter as tk
from typing import Dict, List, Optional

import customtkinter as ctk
from tkinter import messagebox

from app.database.db_manager import DatabaseManager
from app.services.scan_service import ScanService


class SettingsPage(ctk.CTkFrame):
    def __init__(self, master: tk.Misc, db: DatabaseManager, service: ScanService) -> None:
        super().__init__(master, fg_color="transparent")
        self._db = db
        self._service = service
        self._build_ui()

    def _build_ui(self) -> None:
        top = ctk.CTkFrame(self, corner_radius=18)
        top.pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(top, text="Settings", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(top, text="Settings are loaded from .env and database overrides. Realtime monitoring updates immediately; database location changes require restart.", text_color="#9a9ba5", wraplength=1000, justify="left").pack(anchor="w", padx=18, pady=(0, 16))

        body = ctk.CTkScrollableFrame(self, corner_radius=16)
        body.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self._provider_var = tk.StringVar(value=self._service.effective_config.ai_provider)
        self._model_var = tk.StringVar(value=self._service.effective_config.model_name)
        self._timeout_var = tk.StringVar(value=str(self._service.effective_config.ai_request_timeout_seconds))
        self._log_level_var = tk.StringVar(value=self._service.effective_config.log_level)
        self._realtime_var = tk.BooleanVar(value=self._service.realtime_enabled)
        self._database_var = tk.StringVar(value=str(self._service.effective_config.database_path))
        self._folders_text = tk.StringVar(value=self._get_default_folders_text())
        self._scanner_vars: Dict[str, tk.BooleanVar] = {}

        self._field(body, "AI Provider", ctk.CTkComboBox, self._provider_var, ["none", "groq", "gemini", "openai", "ollama"])
        self._field(body, "Model", ctk.CTkEntry, self._model_var)
        self._field(body, "API Timeout (seconds)", ctk.CTkEntry, self._timeout_var)
        self._field(body, "Log Level", ctk.CTkComboBox, self._log_level_var, ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self._field(body, "Database Location", ctk.CTkEntry, self._database_var)
        self._field(body, "Default Scan Folders", ctk.CTkTextbox, self._folders_text)
        self._scanner_section(body)
        ctk.CTkCheckBox(body, text="Enable Realtime Monitoring", variable=self._realtime_var).pack(anchor="w", padx=18, pady=(10, 18))

        ctk.CTkButton(body, text="Save Settings", command=self._save).pack(anchor="e", padx=18, pady=(0, 18))

    def _field(self, parent: tk.Widget, label: str, widget_cls, variable: tk.Variable, values: Optional[List[str]] = None) -> None:
        frame = ctk.CTkFrame(parent, corner_radius=16)
        frame.pack(fill="x", padx=6, pady=8)
        ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=16, pady=(14, 8))
        if widget_cls is ctk.CTkTextbox:
            widget = widget_cls(frame, height=120)
            widget.insert("1.0", variable.get())
            widget.pack(fill="x", padx=16, pady=(0, 14))
            setattr(self, f"_{label.lower().replace(' ', '_')}_widget", widget)
        elif widget_cls is ctk.CTkComboBox:
            widget = widget_cls(frame, values=values or [], variable=variable)
            widget.pack(fill="x", padx=16, pady=(0, 14))
            setattr(self, f"_{label.lower().replace(' ', '_')}_widget", widget)
        else:
            widget = widget_cls(frame, textvariable=variable)
            widget.pack(fill="x", padx=16, pady=(0, 14))
            setattr(self, f"_{label.lower().replace(' ', '_')}_widget", widget)

    def _get_default_folders_text(self) -> str:
        folders = self._db.list_watched_folders()
        if folders:
            return "\n".join(folder.folder_path for folder in folders)
        setting = self._db.get_setting("default_scan_folders", "") or ""
        return setting

    def _scanner_section(self, parent: tk.Widget) -> None:
        frame = ctk.CTkFrame(parent, corner_radius=16)
        frame.pack(fill="x", padx=6, pady=8)
        ctk.CTkLabel(frame, text="Scanners", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=16, pady=(14, 8))
        scanner_specs = [
            ("static_analysis", "Static Analysis Scanner", True),
            ("pe", "PE Scanner", True),
            ("signature", "Signature Scanner", True),
            ("archive", "Archive Scanner", True),
            ("threat_intel", "Threat Intel Scanner", False),
            ("yara", "YARA Scanner", False),
            ("clamav", "ClamAV Scanner", False),
        ]
        enabled_map = self._db.get_scanner_enabled_map()
        for key, label, default_enabled in scanner_specs:
            variable = tk.BooleanVar(value=enabled_map.get(key, default_enabled))
            self._scanner_vars[key] = variable
            ctk.CTkCheckBox(frame, text=label, variable=variable).pack(anchor="w", padx=16, pady=3)

    def _save(self) -> None:
        self._db.set_setting("ai_provider", self._provider_var.get().strip().lower())
        self._db.set_setting("model_name", self._model_var.get().strip())
        self._db.set_setting("ai_request_timeout_seconds", self._timeout_var.get().strip())
        self._db.set_setting("log_level", self._log_level_var.get().strip().upper())
        self._db.set_setting("realtime_monitoring_enabled", "true" if self._realtime_var.get() else "false")
        self._db.set_setting("database_location", self._database_var.get().strip())

        folders_widget = getattr(self, "_default_scan_folders_widget")
        folders_text = folders_widget.get("1.0", "end").strip()
        folders = [line.strip() for line in folders_text.splitlines() if line.strip()]
        if folders:
            self._db.replace_watched_folders(folders)
        self._db.set_setting("default_scan_folders", folders_text)

        for scanner_name, variable in self._scanner_vars.items():
            self._db.set_scanner_enabled(scanner_name, bool(variable.get()))

        self._service.reload_runtime_settings()
        self._service.set_realtime_monitoring(self._realtime_var.get())
        self._service.refresh_watched_folders()
        messagebox.showinfo("Aegis-X", "Settings saved. Some changes apply immediately; database path changes require restart.")
