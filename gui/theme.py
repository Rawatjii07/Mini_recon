"""Shared GUI theme values and ttk setup."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


BG_PRIMARY = "#1a1a2e"
BG_SECONDARY = "#16213e"
BG_CARD = "#0f3460"
BG_TOPBAR = "#12172b"
ACCENT_BLUE = "#378ADD"
TEXT_PRIMARY = "#e0e0e0"
TEXT_MUTED = "#8892a4"
TEXT_SUCCESS = "#2ecc71"
TEXT_WARNING = "#f1c40f"
TEXT_DANGER = "#ff5c7a"
TEXT_INFO = "#66d9ef"
TEXT_LOW = "#8be28b"
BORDER_COLOR = "#2a3b5f"

FONT_BODY = ("Segoe UI", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_HEADING = ("Segoe UI", 14, "bold")
FONT_TITLE = ("Segoe UI", 18, "bold")
FONT_MONO = ("Consolas", 9)


def apply_theme(root: tk.Tk) -> ttk.Style:
    """Apply a dark ttk theme."""

    root.configure(bg=BG_PRIMARY)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(".", background=BG_PRIMARY, foreground=TEXT_PRIMARY, fieldbackground=BG_CARD, font=FONT_BODY)
    style.configure("TFrame", background=BG_PRIMARY)
    style.configure("Card.TFrame", background=BG_CARD, relief="flat", borderwidth=1)
    style.configure("Sidebar.TFrame", background=BG_SECONDARY)
    style.configure("Topbar.TFrame", background=BG_TOPBAR)
    style.configure("TLabel", background=BG_PRIMARY, foreground=TEXT_PRIMARY)
    style.configure("Muted.TLabel", background=BG_PRIMARY, foreground=TEXT_MUTED, font=FONT_SMALL)
    style.configure("Heading.TLabel", background=BG_PRIMARY, foreground=TEXT_PRIMARY, font=FONT_HEADING)
    style.configure("Title.TLabel", background=BG_TOPBAR, foreground=TEXT_PRIMARY, font=FONT_TITLE)
    style.configure("Card.TLabel", background=BG_CARD, foreground=TEXT_PRIMARY)
    style.configure("MutedCard.TLabel", background=BG_CARD, foreground=TEXT_MUTED, font=FONT_SMALL)
    style.configure("Accent.TButton", background=ACCENT_BLUE, foreground="white", borderwidth=0)
    style.map("Accent.TButton", background=[("active", "#2f76bd")])
    style.configure("TButton", background=BG_CARD, foreground=TEXT_PRIMARY, bordercolor=BORDER_COLOR)
    style.configure("TEntry", fieldbackground=BG_CARD, foreground=TEXT_PRIMARY, insertcolor=TEXT_PRIMARY)
    style.configure("TCombobox", fieldbackground=BG_CARD, foreground=TEXT_PRIMARY)
    style.configure("TCheckbutton", background=BG_PRIMARY, foreground=TEXT_PRIMARY)
    style.configure("TNotebook", background=BG_PRIMARY, borderwidth=0)
    style.configure("TNotebook.Tab", background=BG_CARD, foreground=TEXT_PRIMARY, padding=(12, 6))
    style.map("TNotebook.Tab", background=[("selected", BG_TOPBAR)], foreground=[("selected", ACCENT_BLUE)])
    style.configure("Treeview", background=BG_CARD, foreground=TEXT_PRIMARY, fieldbackground=BG_CARD, bordercolor=BORDER_COLOR)
    style.configure("Treeview.Heading", background=BG_TOPBAR, foreground=TEXT_PRIMARY)
    style.configure("Horizontal.TProgressbar", troughcolor=BG_CARD, background=ACCENT_BLUE)
    return style
