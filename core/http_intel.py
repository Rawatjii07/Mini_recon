"""HTTP header, cookie, redirect, and fingerprint checks."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from utils.scope_checker import ScopeChecker, ScopeError


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

COOKIE_FRAMEWORKS = {
    "XSRF-TOKEN": "Laravel",
    "PHPSESSID": "PHP",
    "django_language": "Django",
    "JSESSIONID": "Java Spring",
    "connect.sid": "Node.js Express",
    "csrftoken": "Django",
    "rack.session": "Ruby on Rails",
}


def normalize_url(target: str) -> str:
    """Normalize a target into an HTTP URL."""

    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    scheme, rest = target.split("://", 1)
    if rest.startswith("*."):
        target = f"{scheme}://{rest[2:]}"
    return target


def check_http_intel(
    target: str,
    timeout: float = 5.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> dict[str, Any]:
    """Collect basic HTTP intelligence from one target."""

    url = normalize_url(target)
    result: dict[str, Any] = {
        "url": url,
        "final_url": url,
        "status_code": None,
        "server": None,
        "x_powered_by": None,
        "missing_security_headers": [],
        "cookies_missing_flags": [],
        "detected_frameworks": [],
        "redirects_to_https": False,
        "hsts_present": False,
        "error": None,
    }

    try:
        if scope_checker:
            scope_checker.require_in_scope(url, "HTTP intelligence request")
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "MiniReconHTTPIntel/3.0"},
            proxies=proxies,
            verify=verify,
        )
    except (requests.RequestException, ScopeError) as exc:
        result["error"] = str(exc)
        return result

    result["final_url"] = response.url
    result["status_code"] = response.status_code
    result["server"] = response.headers.get("Server")
    result["x_powered_by"] = response.headers.get("X-Powered-By")
    result["missing_security_headers"] = [
        header for header in SECURITY_HEADERS if header not in response.headers
    ]
    result["hsts_present"] = "Strict-Transport-Security" in response.headers

    original_scheme = urlparse(url).scheme
    final_scheme = urlparse(response.url).scheme
    result["redirects_to_https"] = original_scheme == "http" and final_scheme == "https"

    cookie_findings: list[str] = []
    for cookie in response.cookies:
        missing: list[str] = []
        if not cookie.secure:
            missing.append("Secure")
        rest = {key.lower(): value for key, value in cookie._rest.items()}
        if "httponly" not in rest:
            missing.append("HttpOnly")
        if missing:
            cookie_findings.append(f"{cookie.name} missing {', '.join(missing)}")
    result["cookies_missing_flags"] = cookie_findings
    result["detected_frameworks"] = sorted(
        {
            framework
            for cookie in response.cookies
            for cookie_name, framework in COOKIE_FRAMEWORKS.items()
            if cookie.name.lower() == cookie_name.lower()
        }
    )
    return result


def fetch_robots_paths(
    target: str,
    timeout: float = 5.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
    recursive: bool = False,
    recursive_depth: int = 2,
) -> list[str]:
    """Fetch robots.txt and return paths from Disallow directives."""

    base_url = normalize_url(target).rstrip("/") + "/"
    robots_url = urljoin(base_url, "robots.txt")
    try:
        if scope_checker:
            scope_checker.require_in_scope(robots_url, "robots.txt request")
        response = requests.get(
            robots_url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "MiniReconHTTPIntel/3.0"},
            proxies=proxies,
            verify=verify,
        )
    except (requests.RequestException, ScopeError):
        return []

    if response.status_code >= 400:
        return []

    paths: list[str] = []
    for raw_line in response.text.splitlines():
        line = raw_line.strip()
        if not line.lower().startswith("disallow:"):
            continue
        path = line.split(":", 1)[1].strip()
        if not path or path == "/":
            continue
        if not path.startswith("/"):
            path = f"/{path}"
        paths.append(path)
        if recursive:
            parts = [part for part in path.strip("/").split("/") if part]
            depth = max(1, min(4, recursive_depth))
            for index in range(1, min(len(parts), depth) + 1):
                paths.append("/" + "/".join(parts[:index]) + "/")
    return sorted(set(paths))
