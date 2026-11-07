"""Rule-based next-step suggestions."""

from __future__ import annotations

from typing import Any


def suggestions_for_scan(scan_data: dict[str, Any]) -> list[str]:
    """Generate actionable next-step suggestions from scan findings."""

    suggestions: list[str] = []

    for item in scan_data.get("directories", []):
        path = str(item.get("path", "")).lower()
        if path.endswith("backup.zip"):
            suggestions.append("/backup.zip found -> Download and inspect for credentials or config files")
        if path == "/admin":
            suggestions.append("/admin found -> Test default credentials: admin/admin, admin/password")

    for item in scan_data.get("fuzzing", []):
        attack_type = item.get("attack_type")
        if attack_type == "sqli" and item.get("possible_vulnerability"):
            suggestions.append("SQLi payload triggered -> Run sqlmap on this endpoint and parameter")

    for item in scan_data.get("ports", []):
        if int(item.get("port", 0)) == 22:
            suggestions.append("Port 22 open -> Check for weak SSH credentials")

    for item in scan_data.get("http_intel", []):
        missing = item.get("missing_security_headers", [])
        if "Content-Security-Policy" in missing:
            suggestions.append("CSP header missing -> XSS may succeed here - test further")

    for item in scan_data.get("subdomains", []):
        body_keywords = item.get("keywords", [])
        if "login" in body_keywords:
            suggestions.append("Login page detected on subdomain -> Test for brute-force and SQL injection")

    seen: set[str] = set()
    unique: list[str] = []
    for suggestion in suggestions:
        if suggestion not in seen:
            seen.add(suggestion)
            unique.append(suggestion)
    return unique
