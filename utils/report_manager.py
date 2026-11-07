"""Report management system for auto and important reports."""

from __future__ import annotations

from datetime import datetime
import re
import shutil
from pathlib import Path
from typing import Any

from output.report import render_html_report


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORT_ROOT = PROJECT_ROOT / "output" / "reports"
AUTO_DIR = REPORT_ROOT / "auto"
SAVED_DIR = REPORT_ROOT / "saved"


def _ensure_dirs() -> None:
    AUTO_DIR.mkdir(parents=True, exist_ok=True)
    SAVED_DIR.mkdir(parents=True, exist_ok=True)


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return cleaned.strip("._") or "target"


def _location_path(location: str | Path) -> Path:
    if isinstance(location, Path):
        return location
    normalized = location.lower().strip()
    if normalized == "auto":
        return AUTO_DIR
    if normalized in {"saved", "important"}:
        return SAVED_DIR
    return Path(location)


def enforce_fifo_limit(location: str | Path, limit: int = 100) -> None:
    """Delete oldest reports in one location until count is within limit."""

    directory = _location_path(location)
    directory.mkdir(parents=True, exist_ok=True)
    reports = sorted(
        [path for path in directory.glob("*.html") if path.is_file()],
        key=lambda path: (path.stat().st_ctime, path.name),
    )
    while len(reports) > limit:
        reports.pop(0).unlink(missing_ok=True)


def save_auto_report(scan_data: dict[str, Any], target: str, mode: str) -> Path:
    """Save an automatic HTML report under output/reports/auto."""

    _ensure_dirs()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{timestamp}_{_safe_name(target)}_{_safe_name(mode)}.html"
    path = AUTO_DIR / filename
    report = dict(scan_data)
    report.setdefault("target", target)
    report.setdefault("mode", mode)
    path.write_text(render_html_report(report), encoding="utf-8")
    enforce_fifo_limit(AUTO_DIR, limit=100)
    return path


def save_important_report(filename: str) -> Path:
    """Copy an auto report into the saved/protected report folder."""

    _ensure_dirs()
    source = Path(filename)
    if not source.is_absolute():
        source = AUTO_DIR / filename
    if not source.exists():
        raise FileNotFoundError(f"Report not found: {source}")
    destination = SAVED_DIR / source.name
    shutil.copy2(source, destination)
    enforce_fifo_limit(SAVED_DIR, limit=100)
    return destination


def list_auto_reports() -> list[Path]:
    """Return auto reports sorted newest first."""

    _ensure_dirs()
    return sorted(AUTO_DIR.glob("*.html"), key=lambda path: (path.stat().st_ctime, path.name), reverse=True)


def list_saved_reports() -> list[Path]:
    """Return saved reports sorted newest first."""

    _ensure_dirs()
    return sorted(SAVED_DIR.glob("*.html"), key=lambda path: (path.stat().st_ctime, path.name), reverse=True)


def delete_report(location: str | Path, filename: str) -> bool:
    """Delete one report from a chosen location."""

    directory = _location_path(location)
    path = directory / Path(filename).name
    if not path.exists():
        return False
    path.unlink()
    return True


def get_report_count(location: str | Path) -> int:
    """Return the number of HTML reports in a location."""

    directory = _location_path(location)
    directory.mkdir(parents=True, exist_ok=True)
    return len([path for path in directory.glob("*.html") if path.is_file()])
