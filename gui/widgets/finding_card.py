"""Expandable finding card."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from gui import theme


class FindingCard(ttk.Frame):
    """Simple expandable finding card."""

    def __init__(self, master: tk.Misc, title: str, severity: str, description: str, details: str = "") -> None:
        super().__init__(master, style="Card.TFrame", padding=10)
        self.details_text = details
        self.expanded = False
        top = ttk.Frame(self, style="Card.TFrame")
        top.pack(fill="x")
        self.toggle = ttk.Button(top, text=">", width=3, command=self.toggle_details)
        self.toggle.pack(side="left")
        color = {
            "CRITICAL": theme.TEXT_DANGER,
            "HIGH": theme.TEXT_DANGER,
            "MEDIUM": theme.TEXT_WARNING,
            "LOW": theme.TEXT_LOW,
        }.get(severity.upper(), theme.TEXT_INFO)
        ttk.Label(top, text=severity.upper(), foreground=color, style="Card.TLabel").pack(side="left", padx=(6, 8))
        ttk.Label(top, text=title, style="Card.TLabel", font=("Segoe UI", 10, "bold")).pack(side="left", fill="x", expand=True)
        ttk.Label(self, text=description, style="MutedCard.TLabel", wraplength=760).pack(anchor="w", pady=(6, 0))
        self.details = tk.Text(self, height=1, bg=theme.BG_PRIMARY, fg=theme.TEXT_PRIMARY, relief="flat", wrap="word")

    def toggle_details(self) -> None:
        self.expanded = not self.expanded
        self.toggle.configure(text="v" if self.expanded else ">")
        if self.expanded:
            self.details.configure(state="normal", height=8)
            self.details.delete("1.0", "end")
            self.details.insert("1.0", self.details_text)
            self.details.configure(state="disabled")
            self.details.pack(fill="x", pady=(8, 0))
        else:
            self.details.pack_forget()
