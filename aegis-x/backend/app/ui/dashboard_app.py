"""CustomTkinter desktop shell for Aegis-X."""

from __future__ import annotations

import json
import queue
import tkinter as tk
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk

from app.database.db_manager import DatabaseManager
from app.models.file_report import FileReport, Severity
from app.services.scan_service import ScanService
from app.utils.logger import get_logger

logger = get_logger(__name__)

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

_SEVERITY_COLORS = {
    Severity.LOW: "#2e7d32",
    Severity.MEDIUM: "#f9a825",
    Severity.HIGH: "#ef6c00",
    Severity.CRITICAL: "#c62828",
}


class ReportDetailWindow(ctk.CTkToplevel):
    def __init__(self, parent: tk.Misc, report: FileReport) -> None:
        super().__init__(parent)
        self._report = report
        self.title(f"Aegis-X Report — {report.metadata.filename}")
        self.geometry("1100x820")
        self.minsize(900, 700)
        self._build_ui()

    def _build_ui(self) -> None:
        header = ctk.CTkFrame(self, corner_radius=16)
        header.pack(fill="x", padx=18, pady=(18, 10))

        severity = self._report.risk.severity if self._report.risk else Severity.LOW
        score = self._report.risk.score if self._report.risk else 0.0
        ctk.CTkLabel(header, text=self._report.metadata.filename, font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", padx=16, pady=(14, 2))
        ctk.CTkLabel(header, text=f"{severity.value}  •  {score:.0f}/100  •  {self._report.metadata.absolute_path}", text_color="#9a9ba5").pack(anchor="w", padx=16, pady=(0, 14))

        body = ctk.CTkScrollableFrame(self, corner_radius=16)
        body.pack(fill="both", expand=True, padx=18, pady=10)

        self._section(body, "File Metadata", [
            ("Filename", self._report.metadata.filename),
            ("Folder", str(Path(self._report.metadata.absolute_path).parent)),
            ("Size", f"{self._report.metadata.size_bytes:,} bytes"),
            ("Created", self._report.metadata.created_time.strftime("%Y-%m-%d %H:%M:%S")),
            ("Modified", self._report.metadata.modified_time.strftime("%Y-%m-%d %H:%M:%S")),
            ("MIME Type", self._report.metadata.mime_type),
            ("Entropy", f"{self._report.metadata.entropy:.2f} / 8.0"),
        ])
        self._section(body, "Hashes", [
            ("SHA256", self._report.hashes.sha256 or "—"),
            ("MD5", self._report.hashes.md5 or "—"),
        ])
        self._section(body, "Digital Signature", [
            ("Status", self._report.signature.status.value.replace("_", " ").title()),
            ("Publisher", self._report.signature.publisher or "Unknown"),
            ("Detail", self._report.signature.detail or "—"),
        ])
        if self._report.pe_info is not None:
            pe = self._report.pe_info
            self._section(body, "PE Information", [
                ("Architecture", pe.architecture or "—"),
                ("Type", pe.executable_type or "—"),
                ("ASLR", "Enabled" if pe.aslr_enabled else "Disabled"),
                ("DEP/NX", "Enabled" if pe.dep_nx_enabled else "Disabled"),
                ("CFG", "Enabled" if pe.cfg_enabled else "Disabled"),
                ("Sections", ", ".join(pe.section_names) or "—"),
                ("Suspicious sections", ", ".join(pe.suspicious_sections) or "None"),
                ("Suspicious imports", ", ".join(pe.suspicious_imports) or "None"),
            ])

        if self._report.scanner_results:
            scanners_frame = ctk.CTkFrame(body, corner_radius=16)
            scanners_frame.pack(fill="x", padx=6, pady=8)
            ctk.CTkLabel(scanners_frame, text="Scanner Findings", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(14, 8))
            for result in self._report.scanner_results:
                item = ctk.CTkFrame(scanners_frame, fg_color="transparent")
                item.pack(fill="x", padx=16, pady=6)
                header = f"{result.scanner_name}  |  {result.status.value}  |  {result.execution_time_ms:.0f} ms  |  {result.severity}  |  confidence {result.confidence:.2f}"
                ctk.CTkLabel(item, text=header, font=ctk.CTkFont(size=12, weight="bold"), anchor="w").pack(fill="x")
                if result.evidence:
                    ctk.CTkLabel(item, text="Evidence: " + "; ".join(result.evidence), wraplength=900, justify="left").pack(fill="x", pady=(2, 0))
                if result.errors:
                    ctk.CTkLabel(item, text="Errors: " + "; ".join(result.errors), text_color="#c62828", wraplength=900, justify="left").pack(fill="x", pady=(2, 0))

        if self._report.risk is not None:
            risk_frame = ctk.CTkFrame(body, corner_radius=16)
            risk_frame.pack(fill="x", padx=6, pady=8)
            ctk.CTkLabel(risk_frame, text="Risk Breakdown", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(14, 8))
            triggered = [factor for factor in self._report.risk.factors if factor.triggered]
            if not triggered:
                ctk.CTkLabel(risk_frame, text="No risk factors were triggered.", text_color="#9a9ba5").pack(anchor="w", padx=16, pady=(0, 14))
            for factor in triggered:
                ctk.CTkLabel(risk_frame, text=f"• {factor.description}  (weight {factor.weight:.0f})", wraplength=900, justify="left").pack(anchor="w", padx=16, pady=2)

        if self._report.ai_explanation is not None:
            ai = self._report.ai_explanation
            ai_frame = ctk.CTkFrame(body, corner_radius=16)
            ai_frame.pack(fill="x", padx=6, pady=8)
            ctk.CTkLabel(ai_frame, text=f"AI Explanation ({ai.provider})", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(14, 8))
            if ai.error:
                ctk.CTkLabel(ai_frame, text=f"AI explanation unavailable: {ai.error}", text_color="#9a9ba5").pack(anchor="w", padx=16, pady=(0, 14))
            else:
                for label, value in [
                    ("What it appears to be", ai.what_it_appears_to_be),
                    ("Why the evidence matters", ai.why_evidence_matters),
                    ("Possible attack techniques", ai.possible_attack_techniques),
                    ("Potential impact", ai.potential_impact),
                    ("Recommended precautions", ai.recommended_precautions),
                    ("Confidence level", ai.confidence_level),
                ]:
                    ctk.CTkLabel(ai_frame, text=label, text_color="#9a9ba5", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=16, pady=(8, 0))
                    ctk.CTkLabel(ai_frame, text=value or "—", wraplength=900, justify="left").pack(anchor="w", padx=16, pady=(0, 6))

        footer = ctk.CTkFrame(self, corner_radius=16)
        footer.pack(fill="x", padx=18, pady=(10, 18))
        ctk.CTkButton(footer, text="Copy Report", command=self._copy_report).pack(side="right", padx=10, pady=12)
        ctk.CTkButton(footer, text="Export JSON", command=self._export_json).pack(side="right", padx=10, pady=12)
        ctk.CTkButton(footer, text="Export PDF", command=self._export_pdf_placeholder).pack(side="right", padx=10, pady=12)

    def _section(self, parent: tk.Widget, title: str, rows: List[tuple[str, Any]]) -> None:
        frame = ctk.CTkFrame(parent, corner_radius=16)
        frame.pack(fill="x", padx=6, pady=8)
        ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(14, 6))
        for label, value in rows:
            row = ctk.CTkFrame(frame, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=2)
            ctk.CTkLabel(row, text=label, width=180, anchor="w", text_color="#9a9ba5").pack(side="left")
            ctk.CTkLabel(row, text=str(value), anchor="w", justify="left", wraplength=850).pack(side="left", fill="x", expand=True)

    def _report_text(self) -> str:
        return json.dumps(self._report.model_dump(mode="json"), indent=2)

    def _copy_report(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self._report_text())
        messagebox.showinfo("Aegis-X", "Report copied to clipboard.")

    def _export_json(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON report", "*.json")], initialfile=f"{self._report.metadata.filename}.report.json")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self._report_text())
        messagebox.showinfo("Aegis-X", f"Report saved to:\n{path}")

    def _export_pdf_placeholder(self) -> None:
        messagebox.showinfo("Aegis-X", "PDF export is a placeholder for now.")


from app.ui.pages.dashboard_page import DashboardPage
from app.ui.pages.scanner_page import BrowserScannerPage
from app.ui.pages.files_page import FilesPage
from app.ui.pages.reports_page import ReportsPage
from app.ui.pages.findings_page import FindingsPage
from app.ui.pages.system_page import SystemPage
from app.ui.pages.analytics_page import AnalyticsPage
from app.ui.pages.settings_page import SettingsPage
from app.ui.pages.about_page import AboutPage


class AegisXDashboardApp(ctk.CTk):
    def __init__(self, config, database: DatabaseManager, service: ScanService, system_service) -> None:
        super().__init__()
        self._config = config
        self._db = database
        self._service = service
        self._system_service = system_service
        self._pages: Dict[str, tk.Widget] = {}
        self._current_page: Optional[tk.Widget] = None
        self.title("Aegis-X — Endpoint Security Dashboard")
        self.geometry("1600x960")
        self.minsize(1280, 820)
        self._build_shell()
        self.after(250, self._poll_service_events)
        self.after(1000, self._refresh_pages)

    def _build_shell(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        nav = ctk.CTkFrame(self, width=230, corner_radius=0)
        nav.grid(row=0, column=0, sticky="nsw")
        nav.grid_rowconfigure(8, weight=1)

        ctk.CTkLabel(nav, text="Aegis-X", font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, padx=18, pady=(22, 4), sticky="w")
        ctk.CTkLabel(nav, text="Endpoint Security Dashboard", text_color="#9a9ba5").grid(row=1, column=0, padx=18, pady=(0, 18), sticky="w")

        button_specs = [
            ("Dashboard", "dashboard"),
            ("Browser Scanner", "scanner"),
            ("System Exposure", "system"),
            ("Findings", "findings"),
            ("Files", "files"),
            ("Reports", "reports"),
            ("Analytics", "analytics"),
            ("Settings", "settings"),
            ("About", "about"),
        ]
        for row_index, (label, page_key) in enumerate(button_specs, start=2):
            ctk.CTkButton(
                nav,
                text=label,
                height=42,
                command=lambda k=page_key: self.show_page(k)
            ).grid(row=row_index, column=0, padx=16, pady=6, sticky="ew")

        self._content = ctk.CTkFrame(self, corner_radius=0)
        self._content.grid(row=0, column=1, sticky="nsew")
        self._content.grid_rowconfigure(0, weight=1)
        self._content.grid_columnconfigure(0, weight=1)

        self._pages["dashboard"] = DashboardPage(self._content, self._db, self._open_report)
        self._pages["scanner"] = BrowserScannerPage(self._content, self._db, self._service, self._refresh_pages)
        self._pages["system"] = SystemPage(self._content, self._db, self._system_service)
        self._pages["findings"] = FindingsPage(self._content, self._db)
        self._pages["files"] = FilesPage(self._content, self._db, self._open_report)
        self._pages["reports"] = ReportsPage(self._content, self._db, self._open_report)
        self._pages["analytics"] = AnalyticsPage(self._content, self._db)
        self._pages["settings"] = SettingsPage(self._content, self._db, self._service)
        self._pages["about"] = AboutPage(self._content)

        for page in self._pages.values():
            page.grid(row=0, column=0, sticky="nsew")
            page.grid_remove()

        self._current_page = None
        self._current_key: str = ""
        self.show_page("dashboard")

    def show_page(self, page_key: str) -> None:
        target_page = self._pages.get(page_key)
        if target_page is None:
            return

        # Cleanly hide all pages to prevent z-stacking issues
        for p_key, p_widget in self._pages.items():
            if p_key != page_key:
                p_widget.grid_remove()

        # Display and raise the selected page to top
        target_page.grid(row=0, column=0, sticky="nsew")
        target_page.lift()
        self._current_page = target_page
        self._current_key = page_key

        # Force UI update so tab switches instantly on single click
        self.update_idletasks()
        self.after(10, lambda k=page_key: self._refresh_page(k))

    def _refresh_page(self, page_key: str) -> None:
        page = self._pages.get(page_key)
        if hasattr(page, "refresh"):
            page.refresh()

    def _refresh_pages(self) -> None:
        if hasattr(self, "_current_key") and self._current_key:
            self._refresh_page(self._current_key)

    def _poll_service_events(self) -> None:
        try:
            while True:
                event = self._service.events.get_nowait()
                event_type = event.get("type")
                if event_type in {"report_saved", "scan_complete", "folders_changed", "realtime_changed", "settings_reloaded"}:
                    self._refresh_pages()
                elif event_type == "error":
                    logger.error("%s", event.get("message"))
                elif event_type == "warning":
                    logger.warning("%s", event.get("message"))
        except queue.Empty:
            pass
        self.after(250, self._poll_service_events)

    def _open_report(self, report: FileReport) -> None:
        ReportDetailWindow(self, report)
