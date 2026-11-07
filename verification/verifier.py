"""Coordinator for vulnerability verification modules."""

from __future__ import annotations

from typing import Any

from verification.cors_tester import test_cors
from verification.sqli_verifier import verify_sqli_finding
from verification.xss_verifier import verify_xss_finding
from utils.scope_checker import ScopeChecker


def verify_findings(
    target: str,
    fuzz_results: list[dict[str, Any]],
    timeout: float = 8.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> dict[str, Any]:
    """Verify supported finding types after fuzzing completes."""

    sqli: list[dict[str, Any]] = []
    xss: list[dict[str, Any]] = []
    for item in fuzz_results:
        if not item.get("possible_vulnerability"):
            continue
        attack_type = item.get("attack_type")
        if attack_type == "sqli":
            sqli.append(verify_sqli_finding(item, timeout=timeout, proxies=proxies, verify=verify, scope_checker=scope_checker))
        elif attack_type == "xss":
            xss.append(verify_xss_finding(item, timeout=timeout, proxies=proxies, verify=verify, scope_checker=scope_checker))

    cors = test_cors(target, timeout=min(timeout, 8.0), proxies=proxies, verify=verify, scope_checker=scope_checker)
    confirmed_count = sum(1 for item in [*sqli, *xss, cors] if item.get("confirmed"))
    return {
        "sqli": sqli,
        "xss": xss,
        "cors": cors,
        "confirmed_count": confirmed_count,
        "source": "ACTIVE",
    }
