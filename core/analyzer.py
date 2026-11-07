"""Smart analysis, anomaly clustering, and risk scoring."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


PAYLOAD_TYPES = {
    "sqli": ["' OR", "UNION", "--", "SELECT", "1=1"],
    "xss": ["<script>", "onerror=", "<svg", "alert("],
    "lfi": ["../", "etc/passwd", "%2f"],
    "ssti": ["{{", "${", "7*7"],
}

RISKY_PATHS = {"/backup", "/db", "/admin", "/config", "/.env", "/phpmyadmin", "/wp-admin", "/login"}
RISKY_EXTENSIONS = (".zip", ".sql", ".env", ".bak", ".log")
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]


def classify(payload: str) -> str:
    """Classify a payload into an attack family."""

    lowered = payload.lower()
    for payload_type, patterns in PAYLOAD_TYPES.items():
        for pattern in patterns:
            if pattern.lower() in lowered:
                return payload_type
    return "unknown"


def normalize_fuzz_result(result: Any) -> dict[str, Any]:
    """Store fuzz result in the central dict shape requested by the upgrade."""

    if hasattr(result, "__dict__"):
        result = result.__dict__
    return {
        "payload": result.get("payload", ""),
        "param": result.get("param", ""),
        "status": result.get("status", result.get("status_code")),
        "length": result.get("length", result.get("response_length", 0)),
        "body_preview": result.get("body_preview", ""),
        "attack_type": result.get("attack_type") or classify(result.get("payload", "")),
        "url": result.get("url", ""),
        "possible_vulnerability": bool(result.get("possible_vulnerability", False)),
        "reason": result.get("reason", ""),
    }


def cluster_responses(results: list[dict[str, Any]]) -> dict[tuple[Any, int], list[dict[str, Any]]]:
    """Cluster responses by status code and response length."""

    clusters: dict[tuple[Any, int], list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        key = (result.get("status"), int(result.get("length", 0)))
        clusters[key].append(result)
    return dict(clusters)


def flag_anomalies(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag results that fall outside the majority status/length cluster."""

    if not results:
        return []
    clusters = cluster_responses(results)
    majority_key, _ = Counter({key: len(items) for key, items in clusters.items()}).most_common(1)[0]
    flagged: list[dict[str, Any]] = []
    for result in results:
        if (result.get("status"), int(result.get("length", 0))) != majority_key:
            enriched = dict(result)
            enriched["anomaly"] = True
            enriched["confidence"] = confidence_for_result(enriched)
            enriched["suggestion"] = suggestion_for_fuzz(enriched)
            flagged.append(enriched)
    return flagged


def confidence_for_result(result: dict[str, Any]) -> str:
    """Estimate confidence for a flagged fuzz result."""

    if result.get("status") == 500:
        return "High"
    if result.get("status") in {403, 406} and result.get("attack_type") in {"sqli", "xss"}:
        return "High"
    if result.get("possible_vulnerability"):
        return "Medium"
    return "Low"


def suggestion_for_fuzz(result: dict[str, Any]) -> str:
    """Return a compact next-step suggestion for a fuzz anomaly."""

    if result.get("status") in {403, 406}:
        return "Try URL encoding"
    if result.get("attack_type") == "sqli":
        return "Validate manually with safe SQLi checks"
    if result.get("attack_type") == "xss":
        return "Confirm reflection and output encoding"
    return "Compare response body with baseline"


def format_flagged_result(result: dict[str, Any]) -> str:
    """Render the smart output format for one flagged fuzz result."""

    payload_type = result.get("attack_type", "unknown").upper()
    likely = "Likely WAF triggered" if result.get("status") in {403, 406} else "Anomalous response detected"
    return (
        f"PARAM: {result.get('param')} | PAYLOAD: {result.get('payload')} | "
        f"STATUS: {result.get('status')} | LENGTH: {result.get('length')}\n"
        f"-> Payload type: {payload_type}\n"
        f"-> {likely}\n"
        f"-> Confidence: {result.get('confidence', 'Low')}\n"
        f"-> Suggestion: {result.get('suggestion', 'Review manually')}"
    )


def empty_scan_data() -> dict[str, list[Any]]:
    """Create the central scan data structure."""

    return {
        "subdomains": [],
        "ports": [],
        "directories": [],
        "fuzzing": [],
        "http_intel": [],
        "tls_certificate": [],
        "known_cves": [],
        "dns_intel": [],
        "robots_paths": [],
        "wayback": [],
        "wayback_urls": [],
        "wayback_params": [],
        "old_endpoints": [],
        "fuzzer_targets": [],
        "js_analysis": [],
        "js_discovery_paths": [],
        "origin_discovery": [],
        "verification": [],
        "auth_test": [],
        "fingerprint": [],
        "bounty_context": [],
        "learn_mode": [],
    }


def calculate_risk(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Calculate overall risk score and level from correlated findings."""

    score = 0
    reasons: list[str] = []

    directories = scan_data.get("directories", [])
    for item in directories:
        path = str(item.get("path", "")).lower()
        if path.endswith(RISKY_EXTENSIONS):
            score += 5
            reasons.append(f"Risky exposed file found: {path}")
        if path in {"/admin", "/login"}:
            score += 3
            reasons.append(f"Sensitive page found: {path}")

    for item in scan_data.get("fuzzing", []):
        attack_type = item.get("attack_type") or classify(item.get("payload", ""))
        if attack_type in {"sqli", "xss"} and item.get("possible_vulnerability"):
            score += 4
            reasons.append(f"{attack_type.upper()} payload produced unusual response on {item.get('param')}")

    for item in scan_data.get("ports", []):
        port = int(item.get("port", 0))
        if port in {22, 3306}:
            score += 3
            reasons.append(f"Sensitive service open: {port}")

    for item in scan_data.get("subdomains", []):
        host = str(item.get("host", "")).lower()
        prefix = host.split(".", 1)[0]
        if prefix in {"admin", "api", "dev"}:
            score += 2
            reasons.append(f"Interesting subdomain prefix: {host}")

    for item in scan_data.get("http_intel", []):
        missing = item.get("missing_security_headers", [])
        if missing:
            # Cap header penalty so missing defensive headers alone cannot escalate to CRITICAL
            header_points = min(3, len(missing))
            score += header_points
            reasons.append(f"{len(missing)} missing security headers on {item.get('url')} (+{header_points} pts)")

    for item in scan_data.get("dns_intel", []):
        if not item.get("dmarc_present", True):
            score += 2
            reasons.append("DMARC is missing; email spoofing may be possible")

    has_backup_zip = any(str(item.get("path", "")).lower().endswith("backup.zip") for item in directories)
    has_admin_subdomain = any(
        str(item.get("host", "")).lower().startswith("admin.") for item in scan_data.get("subdomains", [])
    )
    forced_critical = has_backup_zip and has_admin_subdomain

    if forced_critical or score >= 10:
        level = "CRITICAL"
    elif score >= 7:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"

    if forced_critical:
        reasons.append("Cross-correlation: backup.zip found and admin subdomain exists")

    return {"score": score, "level": level, "reasons": reasons}
