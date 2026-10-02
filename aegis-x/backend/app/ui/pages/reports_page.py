"""
Reports page.
"""

from __future__ import annotations

import tkinter as tk
from typing import List

import customtkinter as ctk
from tkinter import ttk

from app.database.db_manager import DatabaseManager
from app.models.file_report import FileReport


class ReportsPage(ctk.CTkFrame):
    """Report-centric browser that focuses on saved report records."""

    def __init__(self, master: tk.Misc, db: DatabaseManager, open_report_callback) -> None:
        super().__init__(master, fg_color="transparent")
        self._db = db
        self._open_report_callback = open_report_callback
        self._reports: List[FileReport] = []
        self._build_ui()

    def _build_ui(self) -> None:
        top = ctk.CTkFrame(self, corner_radius=18)
        top.pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(top, text="Reports", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(top, text="Unified report records with scanner counts, risk score, and AI state.", text_color="#9a9ba5").pack(anchor="w", padx=18, pady=(0, 16))

        controls = ctk.CTkFrame(self, corner_radius=16)
        controls.pack(fill="x", padx=12, pady=(0, 8))
        self._search_var = tk.StringVar()
        ctk.CTkEntry(controls, textvariable=self._search_var, placeholder_text="Search reports by filename or path...").pack(side="left", fill="x", expand=True, padx=10, pady=12)
        ctk.CTkButton(controls, text="Refresh", command=self.refresh).pack(side="right", padx=10, pady=12)

        body = ctk.CTkFrame(self, corner_radius=16)
        body.pack(fill="both", expand=True, padx=12, pady=8)

        self._tree = ttk.Treeview(
            body,
            columns=("filename", "score", "severity", "scanner_count", "ai", "time"),
            show="headings",
            height=18,
        )
        for column, title, width in [
            ("filename", "Filename", 320),
            ("score", "Risk Score", 90),
            ("severity", "Severity", 90),
            ("scanner_count", "Scanners", 90),
            ("ai", "AI", 120),
            ("time", "Time", 160),
        ]:
            self._tree.heading(column, text=title)
            self._tree.column(column, width=width, anchor="w")
        self._tree.pack(fill="both", expand=True, padx=12, pady=12)
        self._tree.bind("<Double-1>", self._open_selected_report)

        self.refresh()

    def refresh(self) -> None:
        self._reports = self._db.list_recent_reports(limit=1000)
        self._tree.delete(*self._tree.get_children())
        search = self._search_var.get().strip().lower()
        for report in self._reports:
            if search and search not in report.metadata.filename.lower() and search not in report.metadata.absolute_path.lower():
                continue
            severity = report.risk.severity.value if report.risk else "Low"
            score = report.risk.score if report.risk else 0.0
            ai_state = "Ready" if report.ai_explanation and not report.ai_explanation.error else "Unavailable"
            self._tree.insert(
                "",
                "end",
                iid=str(report.report_id or report.analyzed_at.timestamp()),
                values=(
                    report.metadata.filename,
                    f"{score:.0f}",
                    severity,
                    str(len(report.scanner_results)),
                    ai_state,
                    report.analyzed_at.strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )

    def _open_selected_report(self, event=None) -> None:  # noqa: ANN001
        selection = self._tree.selection()
        if not selection:
            return
        report_id = selection[0]
        for report in self._reports:
            if str(report.report_id or report.analyzed_at.timestamp()) == report_id:
                self._open_report_callback(report)
                return
