"""Technology fingerprinting helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any

import requests

from core.cve_lookup import lookup_cves
from core.http_intel import normalize_url
from utils.scope_checker import ScopeChecker, ScopeError


DETECTION_RULES = {
    "Next.js": (r"/_next/", r"__NEXT_DATA__"),
    "React": (r"\breact(?:\.production)?(?:\.min)?\.js\b", r"data-reactroot", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"),
    "Vue": (r"\bvue(?:\.runtime)?(?:\.min)?\.js\b", r"data-v-[a-f0-9]{4,}", r"__vue_app__"),
    "Angular": (r"ng-version=[\"']", r"\bng-app\b", r"angular(?:\.min)?\.js"),
    "Django": (r"\bcsrftoken\b", r"name=[\"']csrfmiddlewaretoken[\"']"),
    "Flask": (r"\bwerkzeug\b", r"\bflask_session\b"),
    "Laravel": (r"\blaravel_session\b", r"\bXSRF-TOKEN\b"),
    "Rails": (r"\b_rails\b", r"\bcsrf-param\b", r"\brack\.session\b"),
    "Spring": (r"\bJSESSIONID\b", r"\borg\.springframework\b"),
    "WordPress": (r"/wp-content/", r"/wp-includes/", r"content=[\"']WordPress"),
    "Drupal": (r"/sites/default/", r"Drupal\.settings"),
    "Joomla": (r"\bjoomla!\b", r"/templates/[^\"']+/css/joomla"),
}

VERSION_PATTERNS = {
    "Next.js": re.compile(r"next[/@-]?([0-9]+(?:\.[0-9]+){1,2})", re.IGNORECASE),
    "React": re.compile(r"react[/@-]?([0-9]+(?:\.[0-9]+){1,2})", re.IGNORECASE),
    "Vue": re.compile(r"vue[/@-]?([0-9]+(?:\.[0-9]+){1,2})", re.IGNORECASE),
    "Angular": re.compile(r"ng-version=[\"']([^\"']+)[\"']|angular[/@-]?([0-9]+(?:\.[0-9]+){1,2})", re.IGNORECASE),
    "WordPress": re.compile(r"WordPress\s+([0-9]+(?:\.[0-9]+){1,2})", re.IGNORECASE),
    "Drupal": re.compile(r"Drupal\s+([0-9]+(?:\.[0-9]+){1,2})", re.IGNORECASE),
    "Joomla": re.compile(r"Joomla!?\s+([0-9]+(?:\.[0-9]+){1,2})", re.IGNORECASE),
    "Django": re.compile(r"Django[/ ]([0-9]+(?:\.[0-9]+){1,2})", re.IGNORECASE),
    "Flask": re.compile(r"Flask[/ ]([0-9]+(?:\.[0-9]+){1,2})", re.IGNORECASE),
    "Laravel": re.compile(r"Laravel[/ ]([0-9]+(?:\.[0-9]+){1,2})", re.IGNORECASE),
    "Rails": re.compile(r"Rails[/ ]([0-9]+(?:\.[0-9]+){1,2})", re.IGNORECASE),
    "Spring": re.compile(r"Spring[/ ]([0-9]+(?:\.[0-9]+){1,2})", re.IGNORECASE),
}


@dataclass(frozen=True)
class TechnologyFinding:
    """One detected technology."""

    name: str
    version: str | None
    confidence: str
    evidence: tuple[str, ...]
    source: str = "ACTIVE"


def _version_for(name: str, blob: str) -> str | None:
    pattern = VERSION_PATTERNS.get(name)
    if not pattern:
        return None
    match = pattern.search(blob)
    if not match:
        return None
    for group in match.groups():
        if group:
            return group
    return match.group(1)


def detect_technologies_from_response(
    headers: dict[str, str],
    body: str,
    cookies: requests.cookies.RequestsCookieJar | dict[str, str] | None = None,
) -> list[TechnologyFinding]:
    """Detect technologies from response headers, body, and cookies."""

    cookie_blob = ""
    if cookies is not None:
        if isinstance(cookies, dict):
            cookie_blob = " ".join(f"{key}={value}" for key, value in cookies.items())
        else:
            cookie_blob = " ".join(cookie.name for cookie in cookies)
    header_blob = " ".join(f"{key}: {value}" for key, value in headers.items())
    blob = f"{header_blob}\n{cookie_blob}\n{body[:200000]}"
    lowered_blob = blob.lower()

    findings: list[TechnologyFinding] = []
    for name, patterns in DETECTION_RULES.items():
        evidence: list[str] = []
        for pattern in patterns:
            if re.search(pattern, blob, re.IGNORECASE):
                evidence.append(pattern)
        if not evidence:
            continue
        confidence = "HIGH" if len(evidence) >= 2 else "MEDIUM"
        findings.append(TechnologyFinding(name, _version_for(name, blob), confidence, tuple(evidence)))

    server = headers.get("Server") or headers.get("server")
    powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")
    for header_name, value in (("Server", server), ("X-Powered-By", powered_by)):
        if not value:
            continue
        product = str(value).split()[0].split("/")[0]
        version = None
        match = re.search(r"/([0-9]+(?:\.[0-9]+){1,2})", str(value))
        if match:
            version = match.group(1)
        if product.lower() not in lowered_blob:
            continue
        findings.append(TechnologyFinding(product, version, "MEDIUM", (header_name,)))

    seen: set[tuple[str, str | None]] = set()
    unique: list[TechnologyFinding] = []
    for finding in findings:
        key = (finding.name.lower(), finding.version)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def fingerprint_target(
    target: str,
    timeout: float = 5.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
    cve_limit_per_tech: int = 2,
) -> dict[str, Any]:
    """Fingerprint a target and look up compact CVE hints for detections."""

    url = normalize_url(target)
    try:
        if scope_checker:
            scope_checker.require_in_scope(url, "technology fingerprint request")
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "MiniReconFingerprint/3.0"},
            proxies=proxies,
            verify=verify,
        )
    except (requests.RequestException, ScopeError) as exc:
        return {
            "url": url,
            "technologies": [],
            "cves": [],
            "error": str(exc),
            "source": "ACTIVE",
        }

    technologies = detect_technologies_from_response(dict(response.headers), response.text, response.cookies)
    cves: list[dict[str, str]] = []
    seen_cves: set[str] = set()
    for tech in technologies:
        query = f"{tech.name} {tech.version}" if tech.version else tech.name
        for cve in lookup_cves(query, limit=cve_limit_per_tech, proxies=proxies, verify=verify):
            if cve["id"] in seen_cves:
                continue
            seen_cves.add(cve["id"])
            cves.append(cve)

    return {
        "url": response.url,
        "technologies": [asdict(item) for item in technologies],
        "cves": cves,
        "error": None,
        "source": "ACTIVE",
    }
