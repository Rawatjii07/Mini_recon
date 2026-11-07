"""Stat card widget."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from gui import theme


class StatCard(ttk.Frame):
    """Compact dashboard statistic card."""

    def __init__(self, master: tk.Misc, label: str, value: str = "0") -> None:
        super().__init__(master, style="Card.TFrame", padding=12)
        self.label = ttk.Label(self, text=label, style="MutedCard.TLabel")
        self.value = ttk.Label(self, text=value, style="Card.TLabel", font=("Segoe UI", 18, "bold"))
        self.label.pack(anchor="w")
        self.value.pack(anchor="w", pady=(8, 0))

    def set_value(self, value: str, color: str | None = None) -> None:
        self.value.configure(text=value)
        if color:
            self.value.configure(foreground=color)
