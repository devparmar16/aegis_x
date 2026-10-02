"""
Tkinter popup window that presents a completed FileReport to the user.

This is explicitly called out in the spec as a "temporary desktop
popup" — it renders the report but has no knowledge of how the report
was produced (collectors, risk engine, AI provider), keeping the UI
layer decoupled from analysis internals.
"""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from app.models.file_report import FileReport, Severity
from app.utils.logger import get_logger

logger = get_logger(__name__)

_SEVERITY_COLORS = {
    Severity.LOW: "#2e7d32",
    Severity.MEDIUM: "#f9a825",
    Severity.HIGH: "#ef6c00",
    Severity.CRITICAL: "#c62828",
}

_BG_COLOR = "#1e1f26"
_PANEL_COLOR = "#2a2b35"
_TEXT_COLOR = "#e8e8ec"
_MUTED_COLOR = "#9a9ba5"


class ReportPopup:
    """Renders a single FileReport as a modern-styled Tkinter window."""

    def __init__(self, report: FileReport, parent: Optional[tk.Misc] = None) -> None:
        self._report = report
        self._root = tk.Toplevel(parent) if parent is not None else tk.Tk()
        self._configure_window()
        self._build_ui()

    def _configure_window(self) -> None:
        self._root.title(f"Aegis-X — Download Inspection Report: {self._report.metadata.filename}")
        self._root.geometry("780x760")
        self._root.configure(bg=_BG_COLOR)
        self._root.minsize(600, 500)

    def show(self) -> None:
        """Display the window. If this popup owns the Tk root (no parent
        was supplied), this blocks via mainloop; otherwise it's just a
        Toplevel managed by the caller's existing mainloop.
        """
        if isinstance(self._root, tk.Tk):
            self._root.mainloop()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self._build_header()

        canvas = tk.Canvas(self._root, bg=_BG_COLOR, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self._root, orient="vertical", command=canvas.yview)
        body = tk.Frame(canvas, bg=_BG_COLOR)

        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True, padx=(12, 0))
        scrollbar.pack(side="right", fill="y")

        self._build_section(body, "File Information", self._file_info_rows())
        self._build_section(body, "Hashes", self._hash_rows())
        self._build_section(body, "Digital Signature", self._signature_rows())
        if self._report.pe_info is not None:
            self._build_section(body, "PE Security Features", self._pe_rows())
        self._build_risk_section(body)
        self._build_ai_section(body)
        self._build_footer()

    def _build_header(self) -> None:
        header = tk.Frame(self._root, bg=_PANEL_COLOR, padx=16, pady=14)
        header.pack(fill="x", side="top")

        tk.Label(
            header,
            text=self._report.metadata.filename,
            font=("Segoe UI", 15, "bold"),
            bg=_PANEL_COLOR,
            fg=_TEXT_COLOR,
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        severity = self._report.risk.severity if self._report.risk else Severity.LOW
        score = self._report.risk.score if self._report.risk else 0.0
        color = _SEVERITY_COLORS.get(severity, _MUTED_COLOR)

        badge = tk.Frame(header, bg=color, padx=12, pady=6)
        badge.pack(side="right")
        tk.Label(
            badge,
            text=f"{severity.value.upper()}  ·  {score:.0f}/100",
            font=("Segoe UI", 11, "bold"),
            bg=color,
            fg="white",
        ).pack()

    def _build_section(self, parent: tk.Widget, title: str, rows) -> None:
        frame = tk.Frame(parent, bg=_PANEL_COLOR, padx=14, pady=10)
        frame.pack(fill="x", padx=12, pady=6)

        tk.Label(
            frame, text=title, font=("Segoe UI", 11, "bold"),
            bg=_PANEL_COLOR, fg=_TEXT_COLOR, anchor="w",
        ).pack(fill="x", pady=(0, 6))

        for label, value in rows:
            row = tk.Frame(frame, bg=_PANEL_COLOR)
            row.pack(fill="x", pady=1)
            tk.Label(
                row, text=label, font=("Segoe UI", 9),
                bg=_PANEL_COLOR, fg=_MUTED_COLOR, width=20, anchor="w",
            ).pack(side="left")
            tk.Label(
                row, text=str(value), font=("Segoe UI", 9),
                bg=_PANEL_COLOR, fg=_TEXT_COLOR, anchor="w", justify="left",
                wraplength=560,
            ).pack(side="left", fill="x", expand=True)

    def _build_risk_section(self, parent: tk.Widget) -> None:
        if self._report.risk is None:
            return

        frame = tk.Frame(parent, bg=_PANEL_COLOR, padx=14, pady=10)
        frame.pack(fill="x", padx=12, pady=6)

        tk.Label(
            frame, text="Reasons for Score", font=("Segoe UI", 11, "bold"),
            bg=_PANEL_COLOR, fg=_TEXT_COLOR, anchor="w",
        ).pack(fill="x", pady=(0, 6))

        triggered = [f for f in self._report.risk.factors if f.triggered]
        if not triggered:
            tk.Label(
                frame, text="No risk factors were triggered.",
                font=("Segoe UI", 9), bg=_PANEL_COLOR, fg=_MUTED_COLOR, anchor="w",
            ).pack(fill="x")
        for factor in triggered:
            tk.Label(
                frame,
                text=f"• {factor.description}  (weight {factor.weight:.0f})",
                font=("Segoe UI", 9), bg=_PANEL_COLOR, fg=_TEXT_COLOR,
                anchor="w", justify="left", wraplength=680,
            ).pack(fill="x", pady=1)

    def _build_ai_section(self, parent: tk.Widget) -> None:
        ai = self._report.ai_explanation
        if ai is None:
            return

        frame = tk.Frame(parent, bg=_PANEL_COLOR, padx=14, pady=10)
        frame.pack(fill="x", padx=12, pady=6)

        tk.Label(
            frame, text=f"AI Explanation ({ai.provider})",
            font=("Segoe UI", 11, "bold"), bg=_PANEL_COLOR, fg=_TEXT_COLOR, anchor="w",
        ).pack(fill="x", pady=(0, 6))

        if ai.error:
            tk.Label(
                frame, text=f"AI explanation unavailable: {ai.error}",
                font=("Segoe UI", 9), bg=_PANEL_COLOR, fg=_MUTED_COLOR,
                anchor="w", justify="left", wraplength=680,
            ).pack(fill="x")
            return

        sections = [
            ("What it appears to be", ai.what_it_appears_to_be),
            ("Why the evidence matters", ai.why_evidence_matters),
            ("Possible attack techniques", ai.possible_attack_techniques),
            ("Potential impact", ai.potential_impact),
            ("Recommended precautions", ai.recommended_precautions),
            ("Confidence level", ai.confidence_level),
        ]
        for title, text in sections:
            tk.Label(
                frame, text=title, font=("Segoe UI", 9, "bold"),
                bg=_PANEL_COLOR, fg=_MUTED_COLOR, anchor="w",
            ).pack(fill="x", pady=(6, 0))
            tk.Label(
                frame, text=text or "—", font=("Segoe UI", 9),
                bg=_PANEL_COLOR, fg=_TEXT_COLOR, anchor="w",
                justify="left", wraplength=680,
            ).pack(fill="x")

    def _build_footer(self) -> None:
        footer = tk.Frame(self._root, bg=_BG_COLOR, pady=10)
        footer.pack(fill="x", side="bottom")

        tk.Button(
            footer, text="Close", command=self._root.destroy,
            bg="#3a3b45", fg=_TEXT_COLOR, relief="flat", padx=14, pady=6,
        ).pack(side="right", padx=8)

        tk.Button(
            footer, text="Save Report", command=self._on_save_report,
            bg="#3a3b45", fg=_TEXT_COLOR, relief="flat", padx=14, pady=6,
        ).pack(side="right", padx=8)

        tk.Button(
            footer, text="Copy Report", command=self._on_copy_report,
            bg="#3a3b45", fg=_TEXT_COLOR, relief="flat", padx=14, pady=6,
        ).pack(side="right", padx=8)

    # ------------------------------------------------------------------
    # Row builders
    # ------------------------------------------------------------------

    def _file_info_rows(self):
        m = self._report.metadata
        return [
            ("Path", m.absolute_path),
            ("Size", f"{m.size_bytes:,} bytes"),
            ("Created", m.created_time.strftime("%Y-%m-%d %H:%M:%S")),
            ("Modified", m.modified_time.strftime("%Y-%m-%d %H:%M:%S")),
            ("MIME Type", m.mime_type),
            ("Entropy", f"{m.entropy:.2f} / 8.0"),
            ("Executable", "Yes" if m.is_executable else "No"),
        ]

    def _hash_rows(self):
        h = self._report.hashes
        return [("SHA256", h.sha256 or "—"), ("MD5", h.md5 or "—")]

    def _signature_rows(self):
        s = self._report.signature
        return [
            ("Status", s.status.value.replace("_", " ").title()),
            ("Publisher", s.publisher or "Unknown"),
            ("Detail", s.detail or "—"),
        ]

    def _pe_rows(self):
        pe = self._report.pe_info
        return [
            ("Architecture", pe.architecture or "—"),
            ("Type", pe.executable_type or "—"),
            ("ASLR", "Enabled" if pe.aslr_enabled else "Disabled"),
            ("DEP/NX", "Enabled" if pe.dep_nx_enabled else "Disabled"),
            ("CFG", "Enabled" if pe.cfg_enabled else "Disabled"),
            ("Sections", ", ".join(pe.section_names) or "—"),
            ("Suspicious sections", ", ".join(pe.suspicious_sections) or "None"),
            ("Suspicious imports", ", ".join(pe.suspicious_imports) or "None"),
            ("Compiler hint", pe.compiler_hint or "—"),
        ]

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _report_text(self) -> str:
        return json.dumps(self._report.model_dump(mode="json"), indent=2)

    def _on_copy_report(self) -> None:
        try:
            self._root.clipboard_clear()
            self._root.clipboard_append(self._report_text())
            messagebox.showinfo("Aegis-X", "Report copied to clipboard.")
        except tk.TclError as exc:
            logger.error("Failed to copy report to clipboard: %s", exc)
            messagebox.showerror("Aegis-X", "Could not copy report to clipboard.")

    def _on_save_report(self) -> None:
        try:
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON report", "*.json")],
                initialfile=f"{self._report.metadata.filename}.report.json",
            )
            if not path:
                return
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self._report_text())
            messagebox.showinfo("Aegis-X", f"Report saved to:\n{path}")
        except OSError as exc:
            logger.error("Failed to save report: %s", exc)
            messagebox.showerror("Aegis-X", f"Could not save report: {exc}")


def show_report_popup(report: FileReport) -> None:
    """Convenience entry point: build and display a popup for a report."""
    try:
        popup = ReportPopup(report)
        popup.show()
    except Exception as exc:
        logger.error("Failed to display report popup: %s", exc)
