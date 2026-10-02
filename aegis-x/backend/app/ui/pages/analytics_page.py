"""
Analytics page.
"""

from __future__ import annotations

import tkinter as tk
from datetime import datetime
from pathlib import Path
from typing import Dict

import customtkinter as ctk

from app.database.db_manager import DatabaseManager
from app.models.file_report import Severity


class AnalyticsPage(ctk.CTkFrame):
    """Aggregated analytics view backed by SQLite data and scanner metrics."""

    def __init__(self, master: tk.Misc, db: DatabaseManager) -> None:
        super().__init__(master, fg_color="transparent")
        self._db = db
        self._build_ui()

    def _build_ui(self) -> None:
        top = ctk.CTkFrame(self, corner_radius=18)
        top.pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(top, text="Analytics", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(top, text="Database-backed operational metrics for files, severity trends, and scanner health.", text_color="#9a9ba5").pack(anchor="w", padx=18, pady=(0, 16))

        self._metrics_frame = ctk.CTkFrame(self, corner_radius=16)
        self._metrics_frame.pack(fill="x", padx=12, pady=(0, 8))
        self._cards: Dict[str, ctk.CTkLabel] = {}
        for index, (key, label) in enumerate([
            ("total_files", "Total Files Scanned"),
            ("files_today", "Today's Scans"),
            ("avg_risk", "Average Risk Score"),
            ("scanner_count", "Registered Scanners"),
            ("scanner_runs", "Scanner Runs"),
            ("scanner_failures", "Scanner Failures"),
        ]):
            card = ctk.CTkFrame(self._metrics_frame, corner_radius=16)
            card.grid(row=0, column=index, sticky="nsew", padx=6, pady=6)
            self._metrics_frame.grid_columnconfigure(index, weight=1)
            ctk.CTkLabel(card, text=label, text_color="#9a9ba5").pack(anchor="w", padx=16, pady=(14, 2))
            value = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=22, weight="bold"))
            value.pack(anchor="w", padx=16, pady=(0, 14))
            self._cards[key] = value

        lower = ctk.CTkFrame(self, fg_color="transparent")
        lower.pack(fill="both", expand=True, padx=12, pady=8)
        self._left = ctk.CTkFrame(lower, corner_radius=16)
        self._left.pack(side="left", fill="both", expand=True, padx=(0, 8), pady=4)
        self._right = ctk.CTkFrame(lower, corner_radius=16)
        self._right.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=4)

        ctk.CTkLabel(self._left, text="Top Risk Factors / Most Triggered Rules", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(14, 8))
        self._left_text = ctk.CTkTextbox(self._left, height=280)
        self._left_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        ctk.CTkLabel(self._right, text="Scanner Analytics", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(14, 8))
        self._right_text = ctk.CTkTextbox(self._right, height=280)
        self._right_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))

    def refresh(self) -> None:
        reports = self._db.list_recent_reports(limit=2000)
        file_rows = self._db.list_file_rows(limit=2000)
        scanner_rows = self._db.list_scanner_analytics()

        total_files = len(reports)
        files_today = sum(1 for report in reports if report.analyzed_at.date() == datetime.utcnow().date())
        avg_risk = 0.0
        risk_values = [report.risk.score for report in reports if report.risk]
        if risk_values:
            avg_risk = sum(risk_values) / len(risk_values)

        self._cards["total_files"].configure(text=str(total_files))
        self._cards["files_today"].configure(text=str(files_today))
        self._cards["avg_risk"].configure(text=f"{avg_risk:.1f}")
        self._cards["scanner_count"].configure(text=str(len(scanner_rows)))
        self._cards["scanner_runs"].configure(text=str(sum(int(row.get("total_runs") or 0) for row in scanner_rows)))
        self._cards["scanner_failures"].configure(text=str(sum(int(row.get("failed_runs") or 0) for row in scanner_rows)))

        factor_counter: Dict[str, int] = {}
        risk_report_rows = 0
        for report in reports:
            if report.risk:
                for factor in report.risk.factors:
                    if factor.triggered:
                        factor_counter[factor.description] = factor_counter.get(factor.description, 0) + 1
                risk_report_rows += 1

        folder_counter: Dict[str, int] = {}
        extension_counter: Dict[str, int] = {}
        type_counter: Dict[str, int] = {}
        for row in file_rows:
            folder = str(Path(row["absolute_path"]).parent)
            folder_counter[folder] = folder_counter.get(folder, 0) + 1
            extension = (row.get("extension") or "").lower() or "(none)"
            extension_counter[extension] = extension_counter.get(extension, 0) + 1
            mime_type = row.get("mime_type") or "unknown"
            type_counter[mime_type] = type_counter.get(mime_type, 0) + 1

        self._left_text.delete("1.0", "end")
        self._left_text.insert("end", "Top Risk Factors\n")
        for name, count in sorted(factor_counter.items(), key=lambda item: item[1], reverse=True)[:10]:
            self._left_text.insert("end", f"- {name}: {count}\n")
        self._left_text.insert("end", "\nMost Common File Types\n")
        for name, count in sorted(type_counter.items(), key=lambda item: item[1], reverse=True)[:10]:
            self._left_text.insert("end", f"- {name}: {count}\n")
        self._left_text.insert("end", "\nFiles by Extension\n")
        for name, count in sorted(extension_counter.items(), key=lambda item: item[1], reverse=True)[:10]:
            self._left_text.insert("end", f"- {name}: {count}\n")
        self._left_text.insert("end", "\nMost Scanned Folder\n")
        if folder_counter:
            folder_name, folder_count = max(folder_counter.items(), key=lambda item: item[1])
            self._left_text.insert("end", f"- {folder_name}: {folder_count}\n")

        self._right_text.delete("1.0", "end")
        self._right_text.insert("end", "Scanner Health\n")
        for row in scanner_rows:
            self._right_text.insert(
                "end",
                f"- {row.get('scanner_name')}: runs={row.get('total_runs', 0)} avg={row.get('average_execution_time_ms') or 0:.2f}ms success={row.get('successful_runs', 0)} fail={row.get('failed_runs', 0)} detections={row.get('detection_count', 0)} last={row.get('last_execution_time') or '—'}\n",
            )
        self._right_text.insert("end", "\nRecent High-Risk Files\n")
        for report in sorted(reports, key=lambda item: item.analyzed_at, reverse=True)[:10]:
            score = report.risk.score if report.risk else 0.0
            if score >= 75 or (report.risk and report.risk.severity.value in {Severity.HIGH.value, Severity.CRITICAL.value}):
                self._right_text.insert("end", f"- {report.metadata.filename} ({score:.0f}/100)\n")
        self._right_text.insert("end", "\nRecently Scanned Files\n")
        for report in sorted(reports, key=lambda item: item.analyzed_at, reverse=True)[:10]:
            self._right_text.insert("end", f"- {report.metadata.filename} @ {report.analyzed_at.strftime('%Y-%m-%d %H:%M:%S')}\n")
