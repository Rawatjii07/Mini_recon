"""CORS verification helpers for authorized testing."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

import requests

from core.http_intel import normalize_url
from utils.scope_checker import ScopeChecker, ScopeError


@dataclass(frozen=True)
class CORSOriginResult:
    """CORS behavior for one Origin header."""

    origin: str
    allowed_origin: str | None
    allow_credentials: bool
    risky: bool


@dataclass(frozen=True)
class CORSVerification:
    """CORS verification summary."""

    url: str
    confirmed: bool
    confidence: str
    results: tuple[dict[str, Any], ...]
    evidence: str
    source: str = "ACTIVE"


def build_test_origins(target_url: str) -> tuple[str, ...]:
    """Generate dynamic test origins tailored to the target hostname."""

    parsed = urlparse(target_url)
    host = (parsed.hostname or "target.com").lower()
    return (
        "null",
        "https://evil.com",
        f"https://{host}.evil.com",
        f"https://not{host}",
    )


def test_cors(
    target: str,
    timeout: float = 5.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
    origins: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Test CORS headers with multiple dynamically generated Origin values."""

    url = normalize_url(target)
    if origins is None:
        origins = build_test_origins(url)

    results: list[CORSOriginResult] = []
    errors: list[str] = []

    for origin in origins:
        try:
            if scope_checker:
                scope_checker.require_in_scope(url, "CORS verification request")
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "MiniReconCORSTester/3.0", "Origin": origin},
                proxies=proxies,
                verify=verify,
            )
        except (requests.RequestException, ScopeError) as exc:
            errors.append(str(exc))
            continue

        allowed = response.headers.get("Access-Control-Allow-Origin")
        credentials = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        # Browsers reject Access-Control-Allow-Origin: * when Access-Control-Allow-Credentials is true
        # Real exploitable CORS is when an untrusted/arbitrary origin is reflected with credentials: true
        # or when origin "null" is allowed with credentials: true
        reflected_untrusted = bool(allowed) and (allowed.strip() == origin)
        null_allowed_cred = (origin == "null" and allowed == "null" and credentials)
        arbitrary_origin_cred = reflected_untrusted and credentials
        
        risky = arbitrary_origin_cred or null_allowed_cred or (reflected_untrusted and origin in {"https://evil.com"})
        results.append(CORSOriginResult(origin, allowed, credentials, risky))

    confirmed = any(item.risky for item in results)
    has_high = any(item.risky and item.allow_credentials for item in results)
    confidence = "HIGH" if has_high else "MEDIUM" if confirmed else "LOW"
    
    if has_high:
        evidence = "Arbitrary external origin or 'null' reflected with Access-Control-Allow-Credentials: true"
    elif confirmed:
        evidence = "Arbitrary external origin reflected in Access-Control-Allow-Origin"
    elif errors:
        evidence = f"Requests encountered issues: {'; '.join(errors[:2])}"
    else:
        evidence = "No insecure CORS origin reflection observed"

    return asdict(
        CORSVerification(
            url=url,
            confirmed=confirmed,
            confidence=confidence,
            results=tuple(asdict(item) for item in results),
            evidence=evidence,
        )
    )
