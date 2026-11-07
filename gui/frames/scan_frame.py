"""Main scan page."""

from __future__ import annotations

import json
import queue
import re
import subprocess
import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk

from gui import theme
from gui.config import load_gui_settings
from gui.widgets.finding_card import FindingCard
from gui.widgets.stat_card import StatCard


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class ScanFrame(ttk.Frame):
    """Scan controls and result tabs."""

    def __init__(self, master: tk.Misc, log_queue: queue.Queue) -> None:
        super().__init__(master, style="TFrame")
        self.log_queue = log_queue
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.latest_report: dict = {}
        self._build()

    def _build(self) -> None:
        top = ttk.Frame(self, style="Topbar.TFrame", padding=12)
        top.pack(fill="x")
        ttk.Label(top, text="Scan", style="Title.TLabel").pack(side="left")
        self.progress = ttk.Progressbar(top, mode="indeterminate", length=180)

        controls = ttk.Frame(self, padding=12)
        controls.pack(fill="x")
        ttk.Label(controls, text="Target").grid(row=0, column=0, sticky="w")
        self.target = ttk.Entry(controls)
        self.target.grid(row=0, column=1, sticky="ew", padx=8)
        self.target.insert(0, "example.com")
        ttk.Label(controls, text="Mode").grid(row=0, column=2, sticky="w")
        self.mode = ttk.Combobox(controls, values=["recon", "discover", "fuzz", "all"], state="readonly", width=10)
        self.mode.set("recon")
        self.mode.grid(row=0, column=3, padx=8)
        settings = load_gui_settings()
        self.ai = tk.BooleanVar(value=bool(settings.get("ai_enabled", False)))
        self.stealth = tk.BooleanVar(value=bool(settings.get("stealth", False)))
        self.passive = tk.BooleanVar()
        self.wayback = tk.BooleanVar()
        self.js_analysis = tk.BooleanVar()
        self.fingerprint = tk.BooleanVar()
        self.verify = tk.BooleanVar()
        self.learn = tk.BooleanVar(value=bool(settings.get("learn_enabled", False)))
        options = [
            ("AI", self.ai),
            ("Stealth", self.stealth),
            ("Passive", self.passive),
            ("Wayback", self.wayback),
            ("JS", self.js_analysis),
            ("Fingerprint", self.fingerprint),
            ("Verify", self.verify),
            ("Learn", self.learn),
        ]
        for index, (label, var) in enumerate(options):
            ttk.Checkbutton(controls, text=label, variable=var).grid(row=1, column=index, sticky="w", pady=(8, 0))
        controls.columnconfigure(1, weight=1)

        buttons = ttk.Frame(self, padding=(12, 0, 12, 12))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Start Scan", style="Accent.TButton", command=self.start_scan).pack(side="left")
        ttk.Button(buttons, text="Stop", command=self.stop_scan).pack(side="left", padx=8)
        self.progress.pack_forget()

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.overview = ttk.Frame(self.notebook)
        self.ports = ttk.Frame(self.notebook)
        self.directories = ttk.Frame(self.notebook)
        self.fuzz = ttk.Frame(self.notebook)
        self.tls_dns = ttk.Frame(self.notebook)
        self.js_tab = ttk.Frame(self.notebook)
        self.wayback_tab = ttk.Frame(self.notebook)
        self.ai_tab = ttk.Frame(self.notebook)
        for frame, label in [
            (self.overview, "Overview"),
            (self.ports, "Ports"),
            (self.directories, "Directories"),
            (self.fuzz, "Fuzz Results"),
            (self.tls_dns, "TLS/DNS"),
            (self.js_tab, "JS Analysis"),
            (self.wayback_tab, "Wayback"),
            (self.ai_tab, "AI Analysis"),
        ]:
            self.notebook.add(frame, text=label)
        self._build_overview()
        self._build_trees()

    def _build_overview(self) -> None:
        cards = ttk.Frame(self.overview, padding=10)
        cards.pack(fill="x")
        self.card_ports = StatCard(cards, "Open ports")
        self.card_findings = StatCard(cards, "Findings")
        self.card_subdomains = StatCard(cards, "Subdomains")
        self.card_risk = StatCard(cards, "Risk score", "LOW")
        for index, card in enumerate([self.card_ports, self.card_findings, self.card_subdomains, self.card_risk]):
            card.grid(row=0, column=index, sticky="ew", padx=6)
            cards.columnconfigure(index, weight=1)
        ttk.Label(self.overview, text="Findings", style="Heading.TLabel").pack(anchor="w", padx=16, pady=(8, 4))
        self.findings_canvas = tk.Canvas(self.overview, bg=theme.BG_PRIMARY, highlightthickness=0)
        self.findings_frame = ttk.Frame(self.findings_canvas)
        scroll = ttk.Scrollbar(self.overview, command=self.findings_canvas.yview)
        self.findings_canvas.configure(yscrollcommand=scroll.set)
        self.findings_canvas.create_window((0, 0), window=self.findings_frame, anchor="nw")
        self.findings_frame.bind("<Configure>", lambda _event: self.findings_canvas.configure(scrollregion=self.findings_canvas.bbox("all")))
        self.findings_canvas.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=(0, 12))
        scroll.pack(side="right", fill="y", pady=(0, 12))

    def _tree(self, parent: ttk.Frame, columns: tuple[str, ...]) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=columns, show="headings")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=130, anchor="w")
        tree.pack(fill="both", expand=True, padx=10, pady=10)
        return tree

    def _build_trees(self) -> None:
        self.ports_tree = self._tree(self.ports, ("Port", "Service", "Status", "Banner", "Risk"))
        self.dirs_tree = self._tree(self.directories, ("Path", "Status Code", "Size", "Redirect", "Risk Flag"))
        self.fuzz_tree = self._tree(self.fuzz, ("Parameter", "Payload", "Status", "Length Diff", "Similarity", "Risk", "WAF"))
        self.tls_tree = self._tree(self.tls_dns, ("Type", "Field", "Value"))
        self.js_tree = self._tree(self.js_tab, ("Endpoint", "Source File", "Method", "Risk"))
        self.wayback_tree = self._tree(self.wayback_tab, ("URL", "First Seen", "Last Seen", "Params", "Status"))
        self.ai_text = tk.Text(self.ai_tab, bg=theme.BG_CARD, fg=theme.TEXT_PRIMARY, relief="flat", wrap="word")
        self.ai_text.pack(fill="both", expand=True, padx=10, pady=10)

    def _command(self, output_path: Path) -> list[str]:
        cmd = [sys.executable, "main.py", "--target", self.target.get().strip(), "--mode", self.mode.get(), "--output", str(output_path)]
        settings = load_gui_settings()
        ports = str(settings.get("default_ports", "")).strip()
        scope = str(settings.get("scope_domains", "")).strip()
        threads = int(settings.get("default_threads", 20) or 20)
        timeout = float(settings.get("request_timeout", 5.0) or 5.0)
        if ports:
            cmd.extend(["--ports", ports])
        if scope:
            cmd.extend(["--scope", scope])
        cmd.extend(
            [
                "--dir-threads",
                str(threads),
                "--fuzz-threads",
                str(threads),
                "--subdomain-threads",
                str(threads),
                "--http-timeout",
                str(timeout),
            ]
        )
        if self.ai.get():
            cmd.append("--ai")
        if self.stealth.get():
            cmd.append("--stealth")
        if self.passive.get():
            cmd.append("--passive")
        if self.wayback.get():
            cmd.append("--wayback")
        if self.js_analysis.get():
            cmd.append("--js-analysis")
        if self.fingerprint.get():
            cmd.append("--fingerprint")
        if self.verify.get():
            cmd.append("--verify")
        if self.learn.get():
            cmd.append("--learn")
        return cmd

    def start_scan(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        output = PROJECT_ROOT / "output" / "gui_latest.json"
        self.stop_event.clear()
        self.progress.pack(side="right")
        self.progress.start(10)
        self.log_queue.put(("[*]", "Starting scan"))
        self.worker = threading.Thread(target=self._run_scan, args=(output,), daemon=True)
        self.worker.start()

    def stop_scan(self) -> None:
        self.stop_event.set()
        self.log_queue.put(("[!]", "Stop requested"))

    def _run_scan(self, output: Path) -> None:
        process = subprocess.Popen(
            self._command(output),
            cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert process.stdout is not None
        for line in process.stdout:
            if self.stop_event.is_set():
                process.terminate()
                break
            clean = ANSI_ESCAPE_RE.sub("", line).strip()
            if clean:
                self.log_queue.put(("[*]", clean))
        code = process.wait()
        self.log_queue.put(("[+]" if code == 0 else "[x]", f"Scan finished with code {code}"))
        self.after(0, lambda: self._load_report(output))

    def _load_report(self, output: Path) -> None:
        self.progress.stop()
        self.progress.pack_forget()
        if not output.exists():
            return
        self.latest_report = json.loads(output.read_text(encoding="utf-8"))
        self._populate()

    def _clear_tree(self, tree: ttk.Treeview) -> None:
        for item in tree.get_children():
            tree.delete(item)

    def _populate(self) -> None:
        report = self.latest_report
        ports = report.get("recon", {}).get("open_ports", [])
        dirs = report.get("directory_discovery", [])
        fuzz = report.get("fuzzing", {}).get("results", [])
        subs = report.get("recon", {}).get("subdomains", [])
        risk = report.get("risk", {})
        self.card_ports.set_value(str(len(ports)))
        self.card_findings.set_value(str(len([item for item in fuzz if item.get("possible_vulnerability")]) + len([item for item in dirs if item.get("risk_level") == "HIGH"])))
        self.card_subdomains.set_value(str(len(subs)))
        self.card_risk.set_value(risk.get("level", "LOW"))
        for child in self.findings_frame.winfo_children():
            child.destroy()
        for item in dirs[:20]:
            if item.get("risk_level") == "HIGH":
                FindingCard(self.findings_frame, item.get("path", ""), "HIGH", item.get("note", ""), json.dumps(item, indent=2)).pack(fill="x", padx=4, pady=4)
        for item in fuzz[:20]:
            if item.get("possible_vulnerability"):
                FindingCard(self.findings_frame, item.get("param", ""), item.get("risk_level", "LOW"), item.get("reason", ""), json.dumps(item, indent=2)).pack(fill="x", padx=4, pady=4)
        self._clear_tree(self.ports_tree)
        for item in ports:
            self.ports_tree.insert("", "end", values=(item.get("port"), item.get("service"), "open", item.get("banner", ""), item.get("risk_level", "")))
        self._clear_tree(self.dirs_tree)
        for item in dirs:
            self.dirs_tree.insert("", "end", values=(item.get("path"), item.get("status_code"), "", item.get("final_url"), item.get("risk_level")))
        self._clear_tree(self.fuzz_tree)
        for item in fuzz:
            self.fuzz_tree.insert("", "end", values=(item.get("param"), item.get("payload"), item.get("status_code"), item.get("length_diff"), item.get("similarity_ratio"), item.get("risk_level"), "blocked" if item.get("status_code") in {403, 406} else ""))
        self._populate_misc(report)

    def _populate_misc(self, report: dict) -> None:
        self._clear_tree(self.tls_tree)
        for item in report.get("tls_certificate", []) if isinstance(report.get("tls_certificate"), list) else [report.get("tls_certificate", {})]:
            for key, value in item.items():
                self.tls_tree.insert("", "end", values=("TLS", key, value))
        dns = report.get("dns_intel", {})
        if isinstance(dns, dict):
            for key, value in dns.items():
                self.tls_tree.insert("", "end", values=("DNS", key, value))
        self._clear_tree(self.js_tree)
        for item in report.get("js_analysis", {}).get("endpoints", []):
            self.js_tree.insert("", "end", values=(item.get("endpoint"), item.get("source_file"), item.get("method"), item.get("risk")))
        self._clear_tree(self.wayback_tree)
        for item in report.get("wayback", {}).get("records", [])[:500]:
            self.wayback_tree.insert("", "end", values=(item.get("url"), item.get("first_seen"), item.get("last_seen"), ",".join(item.get("params", [])), item.get("status_code")))
        self.ai_text.delete("1.0", "end")
        ai = report.get("ai_analyses", {})
        self.ai_text.insert("1.0", json.dumps(ai, indent=2) if ai else "AI Analysis is disabled.\nEnable it in Settings > API Keys.")
