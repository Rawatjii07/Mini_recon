"""Left navigation sidebar."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from gui import theme


class NavSidebar(ttk.Frame):
    """Sidebar navigation buttons."""

    def __init__(self, master: tk.Misc, on_select) -> None:
        super().__init__(master, style="Sidebar.TFrame", width=188)
        self.pack_propagate(False)
        ttk.Label(self, text="MiniRecon", style="Title.TLabel").pack(fill="x", padx=14, pady=(16, 20))
        self.buttons: dict[str, ttk.Button] = {}
        for key, label in [
            ("scan", "Scan"),
            ("dashboard", "Dashboard"),
            ("reports", "Reports"),
            ("export", "Export"),
            ("wordlists", "Wordlists"),
            ("settings", "Settings"),
        ]:
            button = ttk.Button(self, text=label, command=lambda item=key: on_select(item))
            button.pack(fill="x", padx=12, pady=4)
            self.buttons[key] = button
        ttk.Label(
            self,
            text="Authorized testing only",
            style="Muted.TLabel",
            wraplength=150,
        ).pack(side="bottom", padx=12, pady=12)
