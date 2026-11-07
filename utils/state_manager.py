"""Scan state persistence for multi-target and resume workflows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_STATE_PATH = Path(__file__).resolve().parents[1] / "output" / "scan_state.json"


def load_targets(path: str | Path) -> list[str]:
    """Load one target per line, ignoring comments and blanks."""

    target_path = Path(path)
    if not target_path.exists():
        raise FileNotFoundError(f"Targets file not found: {target_path}")
    targets: list[str] = []
    for raw_line in target_path.read_text(encoding="utf-8").splitlines():
        item = raw_line.strip()
        if item and not item.startswith("#"):
            targets.append(item)
    return targets


def load_state(path: str | Path = DEFAULT_STATE_PATH) -> dict[str, Any]:
    """Load scan state if it exists."""

    state_path = Path(path)
    if not state_path.exists():
        return {}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_state(
    target: str,
    mode: str,
    last_completed_module: str,
    report: dict[str, Any],
    scan_data: dict[str, Any],
    path: str | Path = DEFAULT_STATE_PATH,
) -> Path:
    """Persist state after a module completes."""

    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "target": target,
        "mode": mode,
        "last_completed_module": last_completed_module,
        "report": report,
        "scan_data": scan_data,
    }
    state_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return state_path


def should_skip(module_name: str, completed: list[str]) -> bool:
    """Return True when resume mode has already completed a module."""

    return module_name in completed
