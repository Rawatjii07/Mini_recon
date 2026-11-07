"""Wordlist management page."""

from __future__ import annotations

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, ttk


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class WordlistFrame(ttk.Frame):
    """Wordlist editor and importer."""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, padding=12)
        self._build()

    def _build(self) -> None:
        ttk.Label(self, text="Wordlists", style="Heading.TLabel").pack(anchor="w")
        for name in ("subdomains.txt", "dirs.txt", "payloads.txt"):
            path = PROJECT_ROOT / "wordlists" / name
            row = ttk.Frame(self)
            row.pack(fill="x", pady=5)
            ttk.Label(row, text=name).pack(side="left")
            ttk.Button(row, text="View/Edit", command=lambda p=path: self.edit(p)).pack(side="right")
            ttk.Button(row, text="Import Additional", command=lambda p=path: self.import_file(p)).pack(side="right", padx=4)

    def edit(self, path: Path) -> None:
        top = tk.Toplevel(self)
        top.title(f"Editing: {path.name}")
        text = tk.Text(top, width=80, height=30)
        text.pack(fill="both", expand=True)
        text.insert("1.0", path.read_text(encoding="utf-8"))
        status = ttk.Label(top, text="")
        status.pack(side="left")

        def update_status() -> None:
            entries = [line for line in text.get("1.0", "end").splitlines() if line.strip() and not line.strip().startswith("#")]
            status.configure(text=f"{len(entries)} entries")

        def remove_dupes() -> None:
            lines = text.get("1.0", "end").splitlines()
            seen = set()
            unique = []
            for line in lines:
                key = line.strip().lower()
                if key and not key.startswith("#"):
                    if key in seen:
                        continue
                    seen.add(key)
                unique.append(line)
            text.delete("1.0", "end")
            text.insert("1.0", "\n".join(unique))
            update_status()

        def sort_lines() -> None:
            entries = sorted({line.strip() for line in text.get("1.0", "end").splitlines() if line.strip() and not line.strip().startswith("#")}, key=str.lower)
            text.delete("1.0", "end")
            text.insert("1.0", "\n".join(entries) + "\n")
            update_status()

        ttk.Button(top, text="Remove Duplicates", command=remove_dupes).pack(side="left")
        ttk.Button(top, text="Sort A-Z", command=sort_lines).pack(side="left")
        ttk.Button(top, text="Save", command=lambda: (path.write_text(text.get("1.0", "end").strip() + "\n", encoding="utf-8"), top.destroy())).pack(side="right")
        ttk.Button(top, text="Cancel", command=top.destroy).pack(side="right")
        update_status()

    def import_file(self, path: Path) -> None:
        source = filedialog.askopenfilename()
        if not source:
            return
        existing = {line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}
        additions = []
        for line in Path(source).read_text(encoding="utf-8").splitlines():
            clean = line.strip()
            if clean and clean.lower() not in existing:
                additions.append(clean)
                existing.add(clean.lower())
        if additions:
            with path.open("a", encoding="utf-8") as handle:
                handle.write("\n" + "\n".join(additions) + "\n")
