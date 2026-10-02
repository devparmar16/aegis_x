"""
Files page.
"""

from __future__ import annotations

import tkinter as tk
from datetime import datetime
from pathlib import Path
from typing import List

import customtkinter as ctk
from tkinter import ttk

from app.database.db_manager import DatabaseManager
from app.models.file_report import FileReport, Severity


class FilesPage(ctk.CTkFrame):
    def __init__(self, master: tk.Misc, db: DatabaseManager, open_report_callback) -> None:
        super().__init__(master, fg_color="transparent")
        self._db = db
        self._open_report_callback = open_report_callback
        self._all_reports: List[FileReport] = []
        self._sorted_column = "analyzed_at"
        self._sort_descending = True
        self._build_ui()

    def _build_ui(self) -> None:
        top = ctk.CTkFrame(self, corner_radius=18)
        top.pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(top, text="Files", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(top, text="Every scanned file appears here. Use search, filters, and sorting to inspect the unified report history.", text_color="#9a9ba5").pack(anchor="w", padx=18, pady=(0, 16))

        filters = ctk.CTkFrame(self, corner_radius=16)
        filters.pack(fill="x", padx=12, pady=(0, 8))
        self._search_var = tk.StringVar()
        self._severity_var = tk.StringVar(value="All")
        self._extension_var = tk.StringVar(value="All")
        self._folder_var = tk.StringVar(value="All")
        self._date_var = tk.StringVar()
        ctk.CTkEntry(filters, textvariable=self._search_var, placeholder_text="Search filename, folder, hash, publisher...").pack(side="left", fill="x", expand=True, padx=10, pady=12)
        self._severity_combo = ctk.CTkComboBox(filters, values=["All", "Low", "Medium", "High", "Critical"], variable=self._severity_var, width=150)
        self._severity_combo.pack(side="left", padx=10, pady=12)
        self._extension_combo = ctk.CTkComboBox(filters, values=["All"], variable=self._extension_var, width=140)
        self._extension_combo.pack(side="left", padx=10, pady=12)
        self._folder_combo = ctk.CTkComboBox(filters, values=["All"], variable=self._folder_var, width=220)
        self._folder_combo.pack(side="left", padx=10, pady=12)
        ctk.CTkButton(filters, text="Refresh", command=self.refresh).pack(side="right", padx=10, pady=12)
        ctk.CTkEntry(filters, textvariable=self._date_var, placeholder_text="Date YYYY-MM-DD", width=160).pack(side="right", padx=10, pady=12)

        body = ctk.CTkFrame(self, corner_radius=16)
        body.pack(fill="both", expand=True, padx=12, pady=8)

        self._tree = ttk.Treeview(
            body,
            columns=("filename", "folder", "file_type", "size", "score", "severity", "publisher", "hash", "time", "status"),
            show="headings",
            height=18,
        )
        headings = {
            "filename": "Filename",
            "folder": "Folder",
            "file_type": "File Type",
            "size": "Size",
            "score": "Risk Score",
            "severity": "Severity",
            "publisher": "Publisher",
            "hash": "Hash (short)",
            "time": "Time",
            "status": "Status",
        }
        widths = {"filename": 200, "folder": 230, "file_type": 130, "size": 110, "score": 90, "severity": 90, "publisher": 160, "hash": 120, "time": 160, "status": 100}
        for column, title in headings.items():
            self._tree.heading(column, text=title, command=lambda c=column: self._sort_by(c))
            self._tree.column(column, width=widths[column], anchor="w")
        self._tree.pack(fill="both", expand=True, padx=12, pady=12)
        self._tree.bind("<Double-1>", self._open_selected_report)

        self.refresh()

    def refresh(self) -> None:
        self._all_reports = self._db.list_recent_reports(limit=1000)
        extensions = sorted({report.metadata.extension or "" for report in self._all_reports if report.metadata.extension})
        folders = sorted({str(Path(report.metadata.absolute_path).parent) for report in self._all_reports})
        self._tree.delete(*self._tree.get_children())
        self._populate_filter_options(["All"] + extensions, ["All"] + folders)
        self._render_rows()

    def _populate_filter_options(self, extension_values: List[str], folder_values: List[str]) -> None:
        self._extension_combo.configure(values=extension_values)
        self._folder_combo.configure(values=folder_values)

    def _filtered_reports(self) -> List[FileReport]:
        reports = list(self._all_reports)
        search = self._search_var.get().strip().lower()
        severity_filter = self._severity_var.get().strip().lower()
        extension_filter = self._extension_var.get().strip().lower()
        date_filter = self._date_var.get().strip()

        if search:
            reports = [
                report for report in reports
                if search in report.metadata.filename.lower()
                or search in report.metadata.absolute_path.lower()
                or search in (report.signature.publisher or "").lower()
                or search in (report.hashes.sha256 or "").lower()
            ]

        if severity_filter != "all":
            reports = [report for report in reports if report.risk and report.risk.severity.value.lower() == severity_filter]

        if extension_filter != "all":
            reports = [report for report in reports if report.metadata.extension.lower() == extension_filter]

        folder_filter = self._folder_var.get().strip().lower()
        if folder_filter != "all":
            reports = [report for report in reports if str(Path(report.metadata.absolute_path).parent).lower() == folder_filter]

        if date_filter:
            try:
                target_date = datetime.strptime(date_filter, "%Y-%m-%d").date()
                reports = [report for report in reports if report.analyzed_at.date() == target_date]
            except ValueError:
                pass

        return reports

    def _render_rows(self) -> None:
        reports = self._filtered_reports()
        reports.sort(key=self._sort_key, reverse=self._sort_descending)
        self._tree.delete(*self._tree.get_children())
        for report in reports:
            severity = report.risk.severity.value if report.risk else "Low"
            score = report.risk.score if report.risk else 0.0
            folder = str(Path(report.metadata.absolute_path).parent)
            row_values = (
                report.metadata.filename,
                folder,
                report.metadata.mime_type,
                f"{report.metadata.size_bytes:,}",
                f"{score:.0f}",
                severity,
                report.signature.publisher or "Unknown",
                (report.hashes.sha256 or "")[:12],
                report.analyzed_at.strftime("%Y-%m-%d %H:%M:%S"),
                "Analyzed",
            )
            self._tree.insert("", "end", iid=str(report.report_id or report.analyzed_at.timestamp()), values=row_values)

    def _sort_key(self, report: FileReport):
        severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        if self._sorted_column == "filename":
            return report.metadata.filename.lower()
        if self._sorted_column == "folder":
            return str(Path(report.metadata.absolute_path).parent).lower()
        if self._sorted_column == "score":
            return report.risk.score if report.risk else 0.0
        if self._sorted_column == "severity":
            return severity_order.get(report.risk.severity.value if report.risk else "Low", 1)
        if self._sorted_column == "file_type":
            return report.metadata.mime_type.lower()
        if self._sorted_column == "publisher":
            return (report.signature.publisher or "").lower()
        if self._sorted_column == "hash":
            return (report.hashes.sha256 or "").lower()
        if self._sorted_column == "time":
            return report.analyzed_at
        return report.analyzed_at

    def _sort_by(self, column: str) -> None:
        if self._sorted_column == column:
            self._sort_descending = not self._sort_descending
        else:
            self._sorted_column = column
            self._sort_descending = True
        self._render_rows()

    def _open_selected_report(self, event=None) -> None:  # noqa: ANN001
        selection = self._tree.selection()
        if not selection:
            return
        iid = selection[0]
        for report in self._filtered_reports():
            if str(report.report_id or report.analyzed_at.timestamp()) == iid:
                self._open_report_callback(report)
                return
