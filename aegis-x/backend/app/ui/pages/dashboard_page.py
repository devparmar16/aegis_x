"""
Dashboard page.
"""

from __future__ import annotations

import tkinter as tk
from typing import Dict

import customtkinter as ctk

from app.database.db_manager import DatabaseManager


class DashboardPage(ctk.CTkFrame):
    def __init__(self, master: tk.Misc, db: DatabaseManager, open_report_callback) -> None:
        super().__init__(master, fg_color="transparent")
        self._db = db
        self._open_report_callback = open_report_callback
        self._cards: Dict[str, ctk.CTkLabel] = {}
        self._activity_frame = None
        self._scan_frame = None
        self._build_ui()

    def _build_ui(self) -> None:
        top = ctk.CTkFrame(self, corner_radius=18)
        top.pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(top, text="Dashboard", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(top, text="Continuous view of analyzed files, recent scans, and severity distribution.", text_color="#9a9ba5").pack(anchor="w", padx=18, pady=(0, 16))

        cards = ctk.CTkFrame(self, fg_color="transparent")
        cards.pack(fill="x", padx=8, pady=4)
        for index, (key, title) in enumerate([
            ("total_files", "Total Files"),
            ("files_today", "Files Today"),
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
        ]):
            frame = ctk.CTkFrame(cards, corner_radius=16)
            frame.grid(row=0, column=index, sticky="nsew", padx=6, pady=6)
            cards.grid_columnconfigure(index, weight=1)
            ctk.CTkLabel(frame, text=title, text_color="#9a9ba5").pack(anchor="w", padx=16, pady=(14, 2))
            label = ctk.CTkLabel(frame, text="0", font=ctk.CTkFont(size=22, weight="bold"))
            label.pack(anchor="w", padx=16, pady=(0, 14))
            self._cards[key] = label

        lower = ctk.CTkFrame(self, fg_color="transparent")
        lower.pack(fill="both", expand=True, padx=8, pady=8)

        self._activity_frame = ctk.CTkFrame(lower, corner_radius=16)
        self._activity_frame.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=4)
        ctk.CTkLabel(self._activity_frame, text="Recent Activity", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(14, 8))
        self._activity_text = ctk.CTkTextbox(self._activity_frame, height=180)
        self._activity_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self._scan_frame = ctk.CTkFrame(lower, corner_radius=16)
        self._scan_frame.pack(side="left", fill="both", expand=True, padx=(8, 4), pady=4)
        ctk.CTkLabel(self._scan_frame, text="Recent Scans", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(14, 8))
        self._scan_text = ctk.CTkTextbox(self._scan_frame, height=180)
        self._scan_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))

    def refresh(self) -> None:
        metrics = self._db.get_dashboard_metrics()
        counts = metrics.get("severity_counts", {})
        self._cards["total_files"].configure(text=str(metrics.get("total_files", 0)))
        self._cards["files_today"].configure(text=str(metrics.get("files_today", 0)))
        self._cards["critical"].configure(text=str(counts.get("Critical", 0)))
        self._cards["high"].configure(text=str(counts.get("High", 0)))
        self._cards["medium"].configure(text=str(counts.get("Medium", 0)))
        self._cards["low"].configure(text=str(counts.get("Low", 0)))

        self._activity_text.delete("1.0", "end")
        for row in metrics.get("recent_activity", []):
            self._activity_text.insert(
                "end",
                f"{row['analyzed_at']}  |  {row['filename']}  |  {row.get('risk_severity') or 'Low'}  |  {row.get('risk_score') or 0:.0f}/100\n",
            )

        self._scan_text.delete("1.0", "end")
        for row in metrics.get("recent_scans", []):
            self._scan_text.insert(
                "end",
                f"{row['started_at']}  |  {row['scan_type']}  |  {row['target_path']}  |  {row['status']}  |  {row.get('report_count', 0)} files\n",
            )
