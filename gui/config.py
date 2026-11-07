"""Local GUI preference storage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "output" / "gui_settings.json"

DEFAULT_GUI_SETTINGS: dict[str, Any] = {
    "default_ports": "80,443",
    "default_threads": 20,
    "request_timeout": 5.0,
    "scope_domains": "",
    "stealth": False,
    "ai_enabled": False,
    "learn_enabled": False,
    "auto_reports_limit": 25,
    "saved_reports_limit": 100,
}


def load_gui_settings() -> dict[str, Any]:
    """Load GUI settings, falling back to stable defaults."""

    if not CONFIG_PATH.exists():
        return dict(DEFAULT_GUI_SETTINGS)
    try:
        loaded = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return dict(DEFAULT_GUI_SETTINGS)
    settings = dict(DEFAULT_GUI_SETTINGS)
    settings.update({key: value for key, value in loaded.items() if key in DEFAULT_GUI_SETTINGS})
    return settings


def save_gui_settings(settings: dict[str, Any]) -> Path:
    """Persist GUI settings to output/gui_settings.json."""

    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    cleaned = dict(DEFAULT_GUI_SETTINGS)
    cleaned.update({key: value for key, value in settings.items() if key in DEFAULT_GUI_SETTINGS})
    CONFIG_PATH.write_text(json.dumps(cleaned, indent=2), encoding="utf-8")
    return CONFIG_PATH
