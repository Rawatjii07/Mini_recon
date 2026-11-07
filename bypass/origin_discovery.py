"""Origin IP discovery and fingerprint comparison helpers.

This module is for authorized testing only. Public-source lookups are passive;
direct IP fingerprint comparison is active and must stay within the user's
approved scope.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import re
import socket
import time
from typing import Any
from urllib.parse import urlparse

import requests

from core.http_intel import normalize_url
from recon.subdomain import normalize_domain
from utils.scope_checker import ScopeChecker, ScopeError


CRT_SH_ENDPOINT = "https://crt.sh/"
DNSDUMPSTER_ENDPOINT = "https://dnsdumpster.com/"
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True)
class OriginCandidate:
    """A possible origin IP and its source."""

    ip: str
    source: str


@dataclass(frozen=True)
class Fingerprint:
    """A compact HTTP fingerprint for comparison."""

    target: str
    url: str
    status_code: int | None
    server: str | None
    title: str
    body_hash: str
    body_length: int
    error: str | None = None
    source: str = "ACTIVE"


@dataclass(frozen=True)
class OriginComparison:
    """Comparison between host and candidate IP fingerprints."""

    ip: str
    matched: bool
    confidence: str
    reasons: tuple[str, ...]
    fingerprint: dict[str, Any]
    source: str = "ACTIVE"


def _valid_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or address.is_link_local or address.is_multicast)


def _extract_ips(text: str) -> list[str]:
    return sorted({ip for ip in IP_PATTERN.findall(text) if _valid_public_ip(ip)})


def _get_with_backoff(
    url: str,
    params: dict[str, str] | None = None,
    timeout: float = 10.0,
    retries: int = 2,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
) -> requests.Response:
    last_error: requests.RequestException | None = None
    for attempt in range(retries + 1):
        try:
            response = requests.get(
                url,
                params=params,
                timeout=timeout,
                headers={"User-Agent": "MiniReconOriginDiscovery/3.0"},
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
    raise RuntimeError(f"Request failed for {url}: {last_error}")


def resolve_current_ips(target: str) -> list[OriginCandidate]:
    """Resolve current A records for a target domain."""

    domain = normalize_domain(target)
    try:
        addresses = socket.gethostbyname_ex(domain)[2]
    except socket.gaierror:
        return []
    return [OriginCandidate(ip=ip, source="current_dns") for ip in sorted(set(addresses)) if _valid_public_ip(ip)]


def query_crtsh_ips(
    target: str,
    timeout: float = 10.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
) -> list[OriginCandidate]:
    """Best-effort crt.sh text lookup for IP-like historical records."""

    domain = normalize_domain(target)
    try:
        response = _get_with_backoff(
            CRT_SH_ENDPOINT,
            params={"q": domain, "output": "json"},
            timeout=timeout,
            proxies=proxies,
            verify=verify,
        )
    except RuntimeError:
        return []
    return [OriginCandidate(ip=ip, source="crt.sh") for ip in _extract_ips(response.text)]


def scrape_dnsdumpster_ips(
    target: str,
    timeout: float = 10.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
) -> list[OriginCandidate]:
    """Best-effort DNSDumpster page scrape for IP-like historical records."""

    domain = normalize_domain(target)
    try:
        response = _get_with_backoff(
            DNSDUMPSTER_ENDPOINT,
            params={"q": domain},
            timeout=timeout,
            proxies=proxies,
            verify=verify,
        )
    except RuntimeError:
        return []
    return [OriginCandidate(ip=ip, source="dnsdumpster") for ip in _extract_ips(response.text)]


def title_from_html(text: str) -> str:
    """Extract an HTML title when present."""

    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return " ".join(match.group(1).split())[:120]


def fingerprint_url(
    url: str,
    host_header: str | None = None,
    timeout: float = 5.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> Fingerprint:
    """Fetch one URL and return a compact fingerprint."""

    headers = {"User-Agent": "MiniReconOriginDiscovery/3.0"}
    if host_header:
        headers["Host"] = host_header
    try:
        if scope_checker:
            scope_checker.require_in_scope(url, "origin fingerprint request")
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers=headers,
            proxies=proxies,
            verify=verify,
        )
        body = response.text
        return Fingerprint(
            target=host_header or urlparse(url).hostname or url,
            url=url,
            status_code=response.status_code,
            server=response.headers.get("Server"),
            title=title_from_html(body),
            body_hash=hashlib.sha256(body[:4096].encode("utf-8", errors="ignore")).hexdigest(),
            body_length=len(response.content),
        )
    except (requests.RequestException, ScopeError) as exc:
        return Fingerprint(
            target=host_header or urlparse(url).hostname or url,
            url=url,
            status_code=None,
            server=None,
            title="",
            body_hash="",
            body_length=0,
            error=str(exc),
        )


def compare_fingerprints(host: Fingerprint, candidate: Fingerprint, ip: str) -> OriginComparison:
    """Compare host and candidate fingerprints."""

    reasons: list[str] = []
    if host.status_code is not None and host.status_code == candidate.status_code:
        reasons.append("same status code")
    if host.server and candidate.server and host.server == candidate.server:
        reasons.append("same Server header")
    if host.title and candidate.title and host.title == candidate.title:
        reasons.append("same HTML title")
    if host.body_hash and candidate.body_hash and host.body_hash == candidate.body_hash:
        reasons.append("same body hash")
    if host.body_length and candidate.body_length:
        delta = abs(host.body_length - candidate.body_length)
        if delta <= max(200, int(host.body_length * 0.10)):
            reasons.append("similar body length")

    score = len(reasons)
    if "same body hash" in reasons or score >= 3:
        confidence = "HIGH"
    elif score == 2:
        confidence = "MEDIUM"
    elif score == 1:
        confidence = "LOW"
    else:
        confidence = "NONE"

    return OriginComparison(
        ip=ip,
        matched=confidence in {"HIGH", "MEDIUM"},
        confidence=confidence,
        reasons=tuple(reasons),
        fingerprint=asdict(candidate),
    )


def collect_origin_candidates(
    target: str,
    timeout: float = 10.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
) -> list[OriginCandidate]:
    """Collect unique origin IP candidates from available sources."""

    candidates = [
        *resolve_current_ips(target),
        *query_crtsh_ips(target, timeout=timeout, proxies=proxies, verify=verify),
        *scrape_dnsdumpster_ips(target, timeout=timeout, proxies=proxies, verify=verify),
    ]
    seen: set[str] = set()
    unique: list[OriginCandidate] = []
    for candidate in candidates:
        if candidate.ip in seen:
            continue
        seen.add(candidate.ip)
        unique.append(candidate)
    return unique


def discover_origin(
    target: str,
    timeout: float = 5.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
    active_probe: bool = True,
) -> dict[str, Any]:
    """Collect origin candidates and optionally compare HTTP fingerprints."""

    domain = normalize_domain(target)
    if scope_checker:
        scope_checker.require_in_scope(domain, "origin discovery target")
    candidates = collect_origin_candidates(domain, timeout=timeout, proxies=proxies, verify=verify)
    result: dict[str, Any] = {
        "domain": domain,
        "candidates": [asdict(candidate) for candidate in candidates],
        "comparisons": [],
        "matches": [],
        "source": "PASSIVE",
    }

    if not active_probe:
        return result

    host_url = normalize_url(domain)
    host_fp = fingerprint_url(host_url, timeout=timeout, proxies=proxies, verify=verify, scope_checker=scope_checker)
    comparisons: list[OriginComparison] = []
    for candidate in candidates:
        for scheme in ("https", "http"):
            candidate_url = f"{scheme}://{candidate.ip}"
            comparison = compare_fingerprints(
                host_fp,
                fingerprint_url(
                    candidate_url,
                    host_header=domain,
                    timeout=timeout,
                    proxies=proxies,
                    verify=verify,
                    scope_checker=None,
                ),
                candidate.ip,
            )
            comparisons.append(comparison)
            if comparison.matched:
                break

    result["host_fingerprint"] = asdict(host_fp)
    result["comparisons"] = [asdict(item) for item in comparisons]
    result["matches"] = [asdict(item) for item in comparisons if item.matched]
    result["source"] = "ACTIVE"
    return result
