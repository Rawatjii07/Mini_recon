"""XSS verification helpers for authorized testing."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import html
from typing import Any

import requests

from fuzzing.fuzzer import build_param_url
from utils.scope_checker import ScopeChecker, ScopeError


# Probe with HTML break-out characters to confirm lack of sanitization
REFLECTION_MARKER = "mr7<xs\"'s>19"
ALPHANUMERIC_MARKER = "mr7xss19"


@dataclass(frozen=True)
class XSSVerification:
    """One XSS verification result."""

    param: str
    url: str
    confirmed: bool
    confidence: str
    reflected: bool
    stored_reflected: bool
    evidence: str
    source: str = "ACTIVE"


def _get_response(
    url: str,
    timeout: float,
    proxies: dict[str, str] | None,
    verify: bool | str,
    scope_checker: ScopeChecker | None,
) -> tuple[int | None, str, dict[str, str], str | None]:
    try:
        if scope_checker:
            scope_checker.require_in_scope(url, "XSS verification request")
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "MiniReconXSSVerifier/3.0"},
            proxies=proxies,
            verify=verify,
        )
        headers = {k.lower(): v for k, v in response.headers.items()}
        return response.status_code, response.text, headers, None
    except (requests.RequestException, ScopeError) as exc:
        return None, "", {}, str(exc)


def _is_html_context(headers: dict[str, str]) -> bool:
    content_type = headers.get("content-type", "").lower()
    return "text/html" in content_type or "application/xhtml+xml" in content_type


def verify_xss_finding(
    finding: dict[str, Any],
    timeout: float = 5.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> dict[str, Any]:
    """Verify reflected or simple stored XSS behavior with context and character validation."""

    base_url = str(finding.get("url", ""))
    param = str(finding.get("param", ""))
    if not base_url or not param:
        return asdict(XSSVerification(param, base_url, False, "NONE", False, False, "missing URL or parameter"))

    # Send special-character probe
    probe_url = build_param_url(base_url, param, REFLECTION_MARKER)
    status, body, headers, error = _get_response(probe_url, timeout, proxies, verify, scope_checker)
    if error:
        return asdict(XSSVerification(param, base_url, False, "NONE", False, False, error))

    is_html = _is_html_context(headers)
    raw_reflected = REFLECTION_MARKER in body
    encoded_probe = html.escape(REFLECTION_MARKER)
    sanitized_reflection = encoded_probe in body

    # Stored check: re-fetch the base URL without probe
    _, second_body, second_headers, _ = _get_response(base_url, timeout, proxies, verify, scope_checker)
    stored_raw_reflected = REFLECTION_MARKER in second_body and _is_html_context(second_headers)

    # Confirmation requires unescaped special characters in an executable HTML context
    if stored_raw_reflected:
        confirmed = True
        confidence = "HIGH"
        evidence = f"Unescaped probe '{REFLECTION_MARKER}' persisted in HTML response after second GET (stored XSS behavior)"
    elif raw_reflected and is_html:
        confirmed = True
        confidence = "HIGH"
        evidence = f"Unescaped probe '{REFLECTION_MARKER}' reflected in text/html response (status {status})"
    elif sanitized_reflection:
        confirmed = False
        confidence = "LOW"
        evidence = f"Probe reflected but safely HTML-encoded as '{encoded_probe}'; not exploitable"
    elif not is_html and (raw_reflected or ALPHANUMERIC_MARKER in body):
        confirmed = False
        confidence = "LOW"
        content_type = headers.get("content-type", "unknown")
        evidence = f"Marker reflected in non-HTML context ({content_type}); does not execute as HTML XSS"
    elif ALPHANUMERIC_MARKER in body:
        confirmed = False
        confidence = "LOW"
        evidence = "Plaintext marker reflected, but special characters are filtered or blocked"
    else:
        confirmed = False
        confidence = "LOW"
        evidence = "Marker was not reflected in the response"

    return asdict(
        XSSVerification(
            param=param,
            url=base_url,
            confirmed=confirmed,
            confidence=confidence,
            reflected=raw_reflected,
            stored_reflected=stored_raw_reflected,
            evidence=evidence,
        )
    )
