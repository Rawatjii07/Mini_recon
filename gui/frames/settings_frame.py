"""Settings page."""

from __future__ import annotations

from pathlib import Path
import os
import tkinter as tk
from tkinter import filedialog, ttk

from gui.config import CONFIG_PATH, load_gui_settings, save_gui_settings


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class SettingsFrame(ttk.Frame):
    """Settings notebook."""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.settings = load_gui_settings()
        self._build()

    def _build(self) -> None:
        self.status = tk.StringVar(value=f"Settings file: {CONFIG_PATH}")
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12, pady=12)
        self._scan_defaults(notebook)
        self._api_keys(notebook)
        self._report_settings(notebook)
        self._wordlists(notebook)
        self._learn_mode(notebook)
        ttk.Label(self, textvariable=self.status).pack(anchor="w", padx=12, pady=(0, 12))

    def _scan_defaults(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Scan Defaults")
        self.default_ports = tk.StringVar(value=str(self.settings.get("default_ports", "")))
        self.default_threads = tk.IntVar(value=int(self.settings.get("default_threads", 20)))
        self.request_timeout = tk.DoubleVar(value=float(self.settings.get("request_timeout", 5.0)))
        self.scope_domains = tk.StringVar(value=str(self.settings.get("scope_domains", "")))
        self.stealth = tk.BooleanVar(value=bool(self.settings.get("stealth", False)))

        rows = [
            ("Default ports", self.default_ports),
            ("Default threads", self.default_threads),
            ("Request timeout", self.request_timeout),
            ("Scope domains", self.scope_domains),
        ]
        for row, (label, variable) in enumerate(rows):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=6)
            ttk.Entry(frame, textvariable=variable).grid(row=row, column=1, sticky="ew", padx=8)
        ttk.Checkbutton(frame, text="Stealth mode", variable=self.stealth).grid(row=4, column=0, sticky="w", pady=6)
        ttk.Button(frame, text="Save Defaults", command=self.save_settings).grid(row=5, column=1, sticky="e", pady=8)
        frame.columnconfigure(1, weight=1)

    def _api_keys(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="API Keys")
        self.ai_enabled = tk.BooleanVar(value=bool(self.settings.get("ai_enabled", False)))
        ttk.Checkbutton(frame, text="AI Analysis enabled", variable=self.ai_enabled).grid(row=0, column=0, sticky="w")
        self.nvidia_key = ttk.Entry(frame, show="*")
        ttk.Label(frame, text="NVIDIA API Key").grid(row=1, column=0, sticky="w", pady=6)
        self.nvidia_key.grid(row=1, column=1, sticky="ew")
        if os.environ.get("NVIDIA_API_KEY"):
            self.nvidia_key.insert(0, os.environ["NVIDIA_API_KEY"])
        ttk.Button(frame, text="Save", command=self.save_api_settings).grid(row=2, column=1, sticky="e")
        frame.columnconfigure(1, weight=1)

    def save_api_settings(self) -> None:
        key = self.nvidia_key.get().strip()
        if key:
            (PROJECT_ROOT / ".env").write_text(f"NVIDIA_API_KEY={key}\n", encoding="utf-8")
        self.save_settings()

    def _report_settings(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Report Settings")
        self.auto_reports_limit = tk.IntVar(value=int(self.settings.get("auto_reports_limit", 25)))
        self.saved_reports_limit = tk.IntVar(value=int(self.settings.get("saved_reports_limit", 100)))
        ttk.Label(frame, text="Auto reports limit").grid(row=0, column=0, sticky="w", pady=6)
        ttk.Spinbox(frame, from_=10, to=100, textvariable=self.auto_reports_limit, width=8).grid(row=0, column=1, sticky="w")
        ttk.Label(frame, text="Saved reports limit").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Spinbox(frame, from_=10, to=250, textvariable=self.saved_reports_limit, width=8).grid(row=1, column=1, sticky="w")
        ttk.Button(frame, text="Save Report Settings", command=self.save_settings).grid(row=2, column=1, sticky="e", pady=8)

    def _wordlists(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Wordlists")
        for name in ("subdomains.txt", "dirs.txt", "payloads.txt"):
            row = ttk.Frame(frame)
            row.pack(fill="x", pady=4)
            path = PROJECT_ROOT / "wordlists" / name
            count = len([line for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")])
            ttk.Label(row, text=f"{name}: {count} entries").pack(side="left")
            ttk.Button(row, text="View/Edit", command=lambda p=path: self.edit_wordlist(p)).pack(side="right")

    def _learn_mode(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Learn Mode")
        self.learn_enabled = tk.BooleanVar(value=bool(self.settings.get("learn_enabled", False)))
        ttk.Checkbutton(frame, text="Enable learn mode by default", variable=self.learn_enabled).pack(anchor="w")
        progress_path = PROJECT_ROOT / "output" / "learn_progress.json"
        ttk.Label(frame, text=f"Progress file: {progress_path}").pack(anchor="w", pady=10)
        ttk.Button(frame, text="Save Learn Settings", command=self.save_settings).pack(anchor="e")

    def save_settings(self) -> None:
        settings = {
            "default_ports": self.default_ports.get().strip(),
            "default_threads": max(1, int(self.default_threads.get())),
            "request_timeout": max(0.5, float(self.request_timeout.get())),
            "scope_domains": self.scope_domains.get().strip(),
            "stealth": bool(self.stealth.get()),
            "ai_enabled": bool(self.ai_enabled.get()),
            "learn_enabled": bool(self.learn_enabled.get()),
            "auto_reports_limit": max(1, int(self.auto_reports_limit.get())),
            "saved_reports_limit": max(1, int(self.saved_reports_limit.get())),
        }
        path = save_gui_settings(settings)
        self.settings = settings
        self.status.set(f"Saved settings to {path}")

    def edit_wordlist(self, path: Path) -> None:
        top = tk.Toplevel(self)
        top.title(f"Editing: {path}")
        text = tk.Text(top, width=80, height=28)
        text.pack(fill="both", expand=True)
        text.insert("1.0", path.read_text(encoding="utf-8"))
        ttk.Button(top, text="Save", command=lambda: (path.write_text(text.get("1.0", "end").strip() + "\n", encoding="utf-8"), top.destroy())).pack(side="right")
        ttk.Button(top, text="Cancel", command=top.destroy).pack(side="right")
