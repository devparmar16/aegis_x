"""
Findings Page.
"""

from __future__ import annotations

import tkinter as tk
from typing import List

import customtkinter as ctk
from tkinter import ttk

from app.database.db_manager import DatabaseManager


class FindingsPage(ctk.CTkFrame):
    def __init__(self, master: tk.Misc, db: DatabaseManager) -> None:
        super().__init__(master, fg_color="transparent")
        self._db = db
        self._build_ui()

    def _build_ui(self) -> None:
        top = ctk.CTkFrame(self, corner_radius=18)
        top.pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(top, text="Investigation Findings", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(top, text="Correlated risks from system exposures and active file scans.", text_color="#9a9ba5").pack(anchor="w", padx=18, pady=(0, 16))

        controls = ctk.CTkFrame(self, corner_radius=16)
        controls.pack(fill="x", padx=12, pady=(0, 8))
        ctk.CTkButton(controls, text="Refresh", command=self.refresh).pack(side="right", padx=10, pady=12)

        body = ctk.CTkFrame(self, corner_radius=16)
        body.pack(fill="both", expand=True, padx=12, pady=8)

        self._tree = ttk.Treeview(
            body,
            columns=("id", "severity", "type", "description", "time"),
            show="headings",
            height=18,
        )
        for column, title, width in [
            ("id", "Finding ID", 100),
            ("severity", "Severity", 100),
            ("type", "Type", 150),
            ("description", "Description", 600),
            ("time", "Time", 160),
        ]:
            self._tree.heading(column, text=title)
            self._tree.column(column, width=width, anchor="w")
        self._tree.pack(fill="both", expand=True, padx=12, pady=12)

        self.refresh()

    def refresh(self) -> None:
        self._tree.delete(*self._tree.get_children())
        # The database query for findings doesn't exist yet, so this will be empty until implemented.
        # But this sets up the UI shell.
