"""Dashboard page."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from gui.widgets.stat_card import StatCard
from utils.report_manager import list_auto_reports, list_saved_reports


class DashboardFrame(ttk.Frame):
    """Report-history dashboard."""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self._build()

    def _build(self) -> None:
        cards = ttk.Frame(self, padding=12)
        cards.pack(fill="x")
        reports = list_auto_reports() + list_saved_reports()
        stats = [
            ("Total Scans", str(len(reports))),
            ("Total Findings", "review reports"),
            ("Most Tested Target", "-"),
            ("Average Risk Score", "-"),
        ]
        for index, (label, value) in enumerate(stats):
            card = StatCard(cards, label, value)
            card.grid(row=0, column=index, sticky="ew", padx=6)
            cards.columnconfigure(index, weight=1)
        self.tree = ttk.Treeview(self, columns=("Date", "Target", "Mode", "Findings", "Risk", "Duration"), show="headings")
        for col in ("Date", "Target", "Mode", "Findings", "Risk", "Duration"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)
        self.tree.pack(fill="both", expand=True, padx=12, pady=12)
        for path in reports[:50]:
            self.tree.insert("", "end", values=(path.name[:19], path.name, "", "", "", ""))
