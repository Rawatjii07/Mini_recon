"""MiniRecon Tkinter desktop app."""

from __future__ import annotations

import queue
import sys
from pathlib import Path
import tkinter as tk
from tkinter import ttk

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gui import theme
from gui.frames.dashboard_frame import DashboardFrame
from gui.frames.export_frame import ExportFrame
from gui.frames.reports_frame import ReportsFrame
from gui.frames.scan_frame import ScanFrame
from gui.frames.settings_frame import SettingsFrame
from gui.frames.wordlist_frame import WordlistFrame
from gui.widgets.log_panel import LogPanel
from gui.widgets.nav_sidebar import NavSidebar


class MiniReconApp(tk.Tk):
    """Main GUI window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("MiniRecon v3.0")
        self.geometry("1320x820")
        self.minsize(1100, 680)
        theme.apply_theme(self)
        self.log_queue: queue.Queue = queue.Queue()
        self._build()
        self.after(100, self.poll_logs)

    def _build(self) -> None:
        self.sidebar = NavSidebar(self, self.show_frame)
        self.sidebar.pack(side="left", fill="y")
        self.content = ttk.Frame(self)
        self.content.pack(side="left", fill="both", expand=True)
        self.log_panel = LogPanel(self)
        self.log_panel.pack(side="right", fill="y")
        self.frames = {
            "scan": ScanFrame(self.content, self.log_queue),
            "dashboard": DashboardFrame(self.content),
            "reports": ReportsFrame(self.content),
            "export": ExportFrame(self.content),
            "wordlists": WordlistFrame(self.content),
            "settings": SettingsFrame(self.content),
        }
        for frame in self.frames.values():
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.show_frame("scan")

    def show_frame(self, key: str) -> None:
        frame = self.frames[key]
        if hasattr(frame, "refresh"):
            frame.refresh()
        frame.tkraise()

    def poll_logs(self) -> None:
        while not self.log_queue.empty():
            level, message = self.log_queue.get()
            self.log_panel.log(level, message)
        self.after(100, self.poll_logs)


def launch() -> None:
    """Launch the GUI."""

    MiniReconApp().mainloop()


if __name__ == "__main__":
    launch()
