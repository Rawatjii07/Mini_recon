"""Right-side live log panel."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk

from gui import theme


class LogPanel(ttk.Frame):
    """Read-only colored log panel."""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, style="Sidebar.TFrame", width=220)
        self.grid_propagate(False)
        header = ttk.Frame(self, style="Sidebar.TFrame")
        header.pack(fill="x", padx=8, pady=(8, 4))
        ttk.Label(header, text="> Live log", style="Muted.TLabel", font=theme.FONT_MONO).pack(side="left")
        ttk.Button(header, text="Clear", command=self.clear).pack(side="right", padx=(4, 0))
        ttk.Button(header, text="Export", command=self.export).pack(side="right")

        body = ttk.Frame(self, style="Sidebar.TFrame")
        body.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.text = tk.Text(
            body,
            bg=theme.BG_PRIMARY,
            fg=theme.TEXT_PRIMARY,
            insertbackground=theme.TEXT_PRIMARY,
            relief="flat",
            wrap="word",
            font=theme.FONT_MONO,
            state="disabled",
            width=28,
        )
        scroll = ttk.Scrollbar(body, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.text.tag_configure("ok", foreground=theme.TEXT_SUCCESS)
        self.text.tag_configure("warn", foreground=theme.TEXT_WARNING)
        self.text.tag_configure("err", foreground=theme.TEXT_DANGER)
        self.text.tag_configure("info", foreground=theme.TEXT_PRIMARY)

    def log(self, level: str, message: str) -> None:
        tag = {"[+]": "ok", "[!]": "warn", "[x]": "err", "[*]": "info"}.get(level, "info")
        self.text.configure(state="normal")
        self.text.insert("end", f"{level} {message}\n", tag)
        self.text.see("end")
        self.text.configure(state="disabled")

    def clear(self) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")

    def export(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if not path:
            return
        Path = __import__("pathlib").Path
        Path(path).write_text(self.text.get("1.0", "end"), encoding="utf-8")
