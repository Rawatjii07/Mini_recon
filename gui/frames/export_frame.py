"""Export page."""

from __future__ import annotations

import shutil
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, ttk

from utils.report_manager import list_auto_reports, list_saved_reports


class ExportFrame(ttk.Frame):
    """Export selected reports."""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.filter = tk.StringVar(value="all")
        self.output_dir = tk.StringVar(value=str(Path.cwd() / "exports"))
        self._build()

    def _build(self) -> None:
        left = ttk.Frame(self, padding=12)
        left.pack(side="left", fill="both", expand=True)
        right = ttk.Frame(self, padding=12)
        right.pack(side="right", fill="both", expand=True)
        ttk.Label(left, text="Reports", style="Heading.TLabel").pack(anchor="w")
        filters = ttk.Frame(left)
        filters.pack(fill="x", pady=6)
        for label in ("all", "auto", "saved"):
            ttk.Button(filters, text=label.title(), command=lambda value=label: self.set_filter(value)).pack(side="left", padx=2)
        self.listbox = tk.Listbox(left)
        self.listbox.pack(fill="both", expand=True)
        ttk.Label(right, text="Export options", style="Heading.TLabel").pack(anchor="w")
        for label in ("HTML Report", "JSON", "TXT", "HackerOne Report Skeleton", "Burp Suite Sitemap"):
            ttk.Checkbutton(right, text=label).pack(anchor="w", pady=2)
        path_row = ttk.Frame(right)
        path_row.pack(fill="x", pady=12)
        ttk.Entry(path_row, textvariable=self.output_dir).pack(side="left", fill="x", expand=True)
        ttk.Button(path_row, text="Browse", command=self.browse).pack(side="right", padx=4)
        ttk.Button(right, text="Export Selected", style="Accent.TButton", command=self.export).pack(anchor="e")
        self.refresh()

    def set_filter(self, value: str) -> None:
        self.filter.set(value)
        self.refresh()

    def refresh(self) -> None:
        self.listbox.delete(0, "end")
        reports = []
        if self.filter.get() in {"all", "auto"}:
            reports.extend(list_auto_reports())
        if self.filter.get() in {"all", "saved"}:
            reports.extend(list_saved_reports())
        for path in reports:
            self.listbox.insert("end", str(path))

    def browse(self) -> None:
        path = filedialog.askdirectory()
        if path:
            self.output_dir.set(path)

    def export(self) -> None:
        selected = self.listbox.curselection()
        if not selected:
            return
        source = Path(self.listbox.get(selected[0]))
        destination_dir = Path(self.output_dir.get())
        destination_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination_dir / source.name)
