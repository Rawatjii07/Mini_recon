"""Wayback Machine intelligence helpers.

This module uses the public Wayback CDX API and does not contact the target
server directly. Use results only within the authorized scope.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import time
from typing import Any
from urllib.parse import parse_qsl, urlparse

import requests

from recon.subdomain import normalize_domain
from utils.scope_checker import ScopeChecker


CDX_ENDPOINT = "https://web.archive.org/cdx"


@dataclass(frozen=True)
class WaybackRecord:
    """One archived URL record returned by the Wayback CDX API."""

    url: str
    first_seen: str
    last_seen: str
    status_code: str
    mimetype: str
    params: tuple[str, ...]
    path: str
    source: str = "PASSIVE"


def _request_with_backoff(
    params: dict[str, str],
    timeout: float = 15.0,
    retries: int = 3,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
) -> requests.Response:
    """Call the CDX API with simple exponential backoff for rate limits."""

    last_error: requests.RequestException | None = None
    for attempt in range(retries + 1):
        try:
            response = requests.get(
                CDX_ENDPOINT,
                params=params,
                timeout=timeout,
                headers={"User-Agent": "MiniReconWayback/3.0"},
                proxies=proxies,
                verify=verify,
            )
            if response.status_code in {429, 503} and attempt < retries:
                time.sleep(2 ** attempt)
                continue
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"Wayback CDX request failed: {last_error}")


def get_historical_records(
    domain: str,
    timeout: float = 15.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
) -> list[WaybackRecord]:
    """Return archived URL records for a domain from the Wayback CDX API."""

    normalized_domain = normalize_domain(domain)
    params = {
        "url": f"*.{normalized_domain}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "collapse": "urlkey",
        "filter": "statuscode:200",
    }
    response = _request_with_backoff(params, timeout=timeout, proxies=proxies, verify=verify)
    rows = response.json()
    if not rows:
        return []
    if rows and rows[0] == ["timestamp", "original", "statuscode", "mimetype"]:
        rows = rows[1:]

    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        if len(row) < 4:
            continue
        timestamp, url, status_code, mimetype = row[:4]
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            continue
        item = grouped.setdefault(
            url,
            {
                "url": url,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "status_code": status_code,
                "mimetype": mimetype,
            },
        )
        item["first_seen"] = min(str(item["first_seen"]), str(timestamp))
        item["last_seen"] = max(str(item["last_seen"]), str(timestamp))

    records: list[WaybackRecord] = []
    for item in grouped.values():
        parsed = urlparse(str(item["url"]))
        params_tuple = tuple(sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}))
        records.append(
            WaybackRecord(
                url=str(item["url"]),
                first_seen=str(item["first_seen"]),
                last_seen=str(item["last_seen"]),
                status_code=str(item["status_code"]),
                mimetype=str(item["mimetype"]),
                params=params_tuple,
                path=parsed.path or "/",
            )
        )
    return sorted(records, key=lambda record: record.url)


def get_historical_urls(
    domain: str,
    timeout: float = 15.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
) -> list[str]:
    """Return archived URLs for a domain."""

    return [record.url for record in get_historical_records(domain, timeout=timeout, proxies=proxies, verify=verify)]


def extract_params_from_urls(urls: list[str]) -> list[str]:
    """Extract unique query parameter names from archived URLs."""

    params: set[str] = set()
    for url in urls:
        parsed = urlparse(url)
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
            if key:
                params.add(key)
    return sorted(params)


def find_old_endpoints(urls: list[str]) -> list[str]:
    """Return unique historical paths that may be hidden or removed today."""

    endpoints: set[str] = set()
    ignored_extensions = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")
    for url in urls:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if path == "/" or path.lower().endswith(ignored_extensions):
            continue
        endpoints.add(path)
    return sorted(endpoints)


def save_wayback_urls(records: list[WaybackRecord], output_path: str | Path) -> Path:
    """Save archived URLs to a text file."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(record.url for record in records), encoding="utf-8")
    return path


def collect_wayback_intel(
    target: str,
    output_path: str | Path,
    timeout: float = 15.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> dict[str, Any]:
    """Collect Wayback URLs, params, old endpoints, and fuzzer candidates."""

    domain = normalize_domain(target)
    if scope_checker:
        scope_checker.require_in_scope(domain, "Wayback target")

    records = get_historical_records(domain, timeout=timeout, proxies=proxies, verify=verify)
    urls = [record.url for record in records]
    saved_path = save_wayback_urls(records, output_path)
    params = extract_params_from_urls(urls)
    old_endpoints = find_old_endpoints(urls)
    fuzzer_targets = sorted({record.url for record in records if record.params})

    return {
        "domain": domain,
        "records": [asdict(record) for record in records],
        "urls": urls,
        "params": params,
        "old_endpoints": old_endpoints,
        "fuzzer_targets": fuzzer_targets,
        "saved_path": str(saved_path),
        "source": "PASSIVE",
    }
