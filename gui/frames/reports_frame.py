"""Reports management page."""

from __future__ import annotations

import os
import webbrowser
import tkinter as tk
from tkinter import messagebox, ttk

from utils.report_manager import delete_report, get_report_count, list_auto_reports, list_saved_reports, save_important_report


class ReportsFrame(ttk.Frame):
    """Auto and saved report browser."""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.current = "auto"
        self._build()

    def _build(self) -> None:
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        self.header = ttk.Label(top, text="", style="Heading.TLabel")
        self.header.pack(side="left")
        ttk.Button(top, text="Auto", command=lambda: self.set_location("auto")).pack(side="right", padx=4)
        ttk.Button(top, text="Saved", command=lambda: self.set_location("saved")).pack(side="right")
        self.progress = ttk.Progressbar(self, maximum=100)
        self.progress.pack(fill="x", padx=10)
        self.tree = ttk.Treeview(self, columns=("Filename", "Target", "Date", "Risk", "Size"), show="headings")
        for col in ("Filename", "Target", "Date", "Risk", "Size"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.tree.bind("<Double-1>", lambda _event: self.view_selected())
        bottom = ttk.Frame(self, padding=10)
        bottom.pack(fill="x")
        ttk.Button(bottom, text="View", command=self.view_selected).pack(side="left")
        ttk.Button(bottom, text="Save ->", command=self.save_selected).pack(side="left", padx=6)
        ttk.Button(bottom, text="Delete", command=self.delete_selected).pack(side="left")
        ttk.Button(bottom, text="Refresh", command=self.refresh).pack(side="right")
        self.warning = ttk.Label(self, text="", style="Muted.TLabel")
        self.warning.pack(anchor="w", padx=12)
        self.refresh()

    def set_location(self, location: str) -> None:
        self.current = location
        self.refresh()

    def refresh(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        reports = list_auto_reports() if self.current == "auto" else list_saved_reports()
        count = get_report_count(self.current)
        label = "Auto Reports" if self.current == "auto" else "Saved Reports"
        suffix = "" if self.current == "auto" else "  Protected - not affected by auto-deletion"
        self.header.configure(text=f"{label} - {count}/100 slots used{suffix}")
        self.progress.configure(value=count)
        self.warning.configure(text="Approaching limit - oldest will auto-delete soon" if count > 90 else "")
        for path in reports:
            stat = path.stat()
            self.tree.insert("", "end", values=(path.name, self._target_from_name(path.name), path.stat().st_mtime, "", f"{stat.st_size // 1024} KB"))

    def _target_from_name(self, name: str) -> str:
        parts = name.replace(".html", "").split("_")
        return parts[2] if len(parts) > 2 else ""

    def _selected_name(self) -> str | None:
        selected = self.tree.selection()
        if not selected:
            return None
        return str(self.tree.item(selected[0], "values")[0])

    def view_selected(self) -> None:
        name = self._selected_name()
        if not name:
            return
        reports = list_auto_reports() if self.current == "auto" else list_saved_reports()
        for path in reports:
            if path.name == name:
                webbrowser.open(path.resolve().as_uri())
                return

    def save_selected(self) -> None:
        name = self._selected_name()
        if name and self.current == "auto":
            save_important_report(name)
            self.refresh()

    def delete_selected(self) -> None:
        name = self._selected_name()
        if not name:
            return
        if messagebox.askyesno("Delete report", f"Delete {name}?"):
            delete_report(self.current, name)
            self.refresh()
