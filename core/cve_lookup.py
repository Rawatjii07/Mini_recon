"""Known CVE lookup through the public NIST NVD API."""

from __future__ import annotations

import re
from typing import Any

import requests


NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _severity(metrics: dict[str, Any]) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            return values[0].get("cvssData", {}).get("baseSeverity") or values[0].get("baseSeverity") or "UNKNOWN"
    return "UNKNOWN"


def _description(cve: dict[str, Any]) -> str:
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return item.get("value", "")[:220]
    return ""


def lookup_cves(
    keyword: str,
    limit: int = 5,
    timeout: float = 8.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
) -> list[dict[str, str]]:
    """Search NVD by keyword and return compact CVE records."""

    keyword = " ".join(keyword.split())
    if not keyword:
        return []

    try:
        response = requests.get(
            NVD_ENDPOINT,
            params={"keywordSearch": keyword, "resultsPerPage": limit},
            timeout=timeout,
            headers={"User-Agent": "MiniReconCVELookup/3.0"},
            proxies=proxies,
            verify=verify,
        )
        response.raise_for_status()
    except requests.RequestException:
        return []

    records: list[dict[str, str]] = []
    for item in response.json().get("vulnerabilities", [])[:limit]:
        cve = item.get("cve", {})
        records.append(
            {
                "query": keyword,
                "id": cve.get("id", "UNKNOWN"),
                "severity": _severity(cve.get("metrics", {})),
                "description": _description(cve),
            }
        )
    return records


def lookup_http_cves(
    http_info: dict[str, Any],
    limit: int = 5,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
) -> list[dict[str, str]]:
    """Look up CVEs for detected Server and X-Powered-By header values."""

    seen: set[str] = set()
    findings: list[dict[str, str]] = []
    for header_value in (http_info.get("server"), http_info.get("x_powered_by")):
        if not header_value:
            continue
        header_str = str(header_value).strip()
        # Avoid querying generic words without version numbers (e.g. 'cloudflare' or 'nginx' alone)
        if not re.search(r"\d+\.\d+", header_str):
            continue
        for cve in lookup_cves(header_str, limit=limit, proxies=proxies, verify=verify):
            key = cve["id"]
            if key in seen:
                continue
            seen.add(key)
            findings.append(cve)
            if len(findings) >= limit:
                return findings
    return findings
