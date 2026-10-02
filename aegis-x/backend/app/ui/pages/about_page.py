"""
About page.
"""

from __future__ import annotations

import tkinter as tk

import customtkinter as ctk


class AboutPage(ctk.CTkFrame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, fg_color="transparent")
        frame = ctk.CTkFrame(self, corner_radius=18)
        frame.pack(fill="both", expand=True, padx=12, pady=12)
        ctk.CTkLabel(frame, text="About Aegis-X", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=18, pady=(16, 6))
        ctk.CTkLabel(frame, text="Aegis-X is a desktop endpoint security platform built around collectors, a deterministic risk engine, optional AI explanations, and SQLite-backed reporting.", wraplength=1000, justify="left").pack(anchor="w", padx=18, pady=(0, 12))
        ctk.CTkLabel(frame, text="This desktop shell keeps the scanning pipeline separate from the UI so future modules can be added without coupling the collectors to the interface.", text_color="#9a9ba5", wraplength=1000, justify="left").pack(anchor="w", padx=18, pady=(0, 12))
