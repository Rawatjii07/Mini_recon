"""JavaScript analysis for endpoints, secrets, routes, and comments."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from html.parser import HTMLParser
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from core.http_intel import normalize_url
from utils.scope_checker import ScopeChecker, ScopeError


SCRIPT_ENDPOINT_PATTERNS = [
    re.compile(r"\bfetch\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"\baxios\.(?:get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"\baxios\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"\bopen\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE)['\"]\s*,\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"\$\.ajax\(\s*\{[^}]*url\s*:\s*['\"]([^'\"]+)['\"]", re.IGNORECASE | re.DOTALL),
    re.compile(r"\burl\s*:\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
]

PATH_STRING_PATTERN = re.compile(r"['\"]((?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+){1,})['\"]")
URL_PATTERN = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
COMMENT_PATTERN = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)

SECRET_PATTERNS = {
    "AWS Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Bearer Token": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.IGNORECASE),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "API Key": re.compile(r"(?i)\b(api[_-]?key|apikey|client[_-]?secret|secret[_-]?key)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
    "Token": re.compile(r"(?i)\b(token|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"]([^'\"]{12,})['\"]"),
    "Password": re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]([^'\"]{6,})['\"]"),
}


@dataclass(frozen=True)
class ScriptSource:
    """A script URL found in HTML."""

    url: str
    source: str = "ACTIVE"


@dataclass(frozen=True)
class EndpointFinding:
    """An endpoint-like string found in JavaScript."""

    endpoint: str
    source_file: str
    method: str
    risk: str
    source: str = "ACTIVE"


@dataclass(frozen=True)
class SecretFinding:
    """A potential secret-like value found in JavaScript."""

    type: str
    value: str
    masked_value: str
    source_file: str
    line: int
    source: str = "ACTIVE"


@dataclass(frozen=True)
class CommentFinding:
    """A JavaScript comment containing interesting text."""

    text: str
    source_file: str
    line: int
    source: str = "ACTIVE"


class ScriptHTMLParser(HTMLParser):
    """Extract script source URLs from HTML."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        attrs_dict = {key.lower(): value for key, value in attrs}
        src = attrs_dict.get("src")
        if src:
            self.scripts.append(urljoin(self.base_url, src))


def _line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}***{value[-4:]}"


def _request_text(
    url: str,
    timeout: float,
    proxies: dict[str, str] | None,
    verify: bool | str,
    scope_checker: ScopeChecker | None,
) -> str:
    if scope_checker:
        scope_checker.require_in_scope(url, "JavaScript analysis request")
    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "MiniReconJSAnalyzer/3.0"},
        proxies=proxies,
        verify=verify,
    )
    response.raise_for_status()
    return response.text


def extract_script_sources(html: str, base_url: str) -> list[str]:
    """Extract all external script src URLs from HTML."""

    parser = ScriptHTMLParser(base_url)
    parser.feed(html)
    return sorted(set(parser.scripts))


def _risk_for_endpoint(endpoint: str) -> str:
    lowered = endpoint.lower()
    if any(token in lowered for token in ("admin", "token", "secret", "auth", "debug", "internal")):
        return "HIGH"
    if any(token in lowered for token in ("api", "graphql", "login", "upload")):
        return "MEDIUM"
    return "LOW"


def _method_for_match(pattern: re.Pattern[str], text: str) -> str:
    lowered = text.lower()
    if "post" in lowered:
        return "POST"
    if "put" in lowered:
        return "PUT"
    if "patch" in lowered:
        return "PATCH"
    if "delete" in lowered:
        return "DELETE"
    return "GET"


def extract_endpoints(js_text: str, source_file: str) -> list[EndpointFinding]:
    """Extract API endpoints and path strings from JavaScript."""

    findings: list[EndpointFinding] = []
    seen: set[tuple[str, str]] = set()
    for pattern in SCRIPT_ENDPOINT_PATTERNS:
        for match in pattern.finditer(js_text):
            endpoint = match.group(1).strip()
            if not endpoint or endpoint.startswith(("data:", "mailto:", "javascript:")):
                continue
            method = _method_for_match(pattern, match.group(0))
            key = (endpoint, method)
            if key in seen:
                continue
            seen.add(key)
            findings.append(EndpointFinding(endpoint, source_file, method, _risk_for_endpoint(endpoint)))

    for pattern in (URL_PATTERN, PATH_STRING_PATTERN):
        for match in pattern.finditer(js_text):
            endpoint = match.group(1) if pattern is PATH_STRING_PATTERN else match.group(0)
            endpoint = endpoint.strip()
            if len(endpoint) < 2 or endpoint.startswith(("//", "/*")):
                continue
            key = (endpoint, "GET")
            if key in seen:
                continue
            seen.add(key)
            findings.append(EndpointFinding(endpoint, source_file, "GET", _risk_for_endpoint(endpoint)))
    return findings


def extract_secrets(js_text: str, source_file: str) -> list[SecretFinding]:
    """Extract potential hardcoded secrets from JavaScript."""

    findings: list[SecretFinding] = []
    seen: set[tuple[str, str]] = set()
    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(js_text):
            value = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
            key = (secret_type, value)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                SecretFinding(
                    type=secret_type,
                    value=value,
                    masked_value=_mask(value),
                    source_file=source_file,
                    line=_line_number(js_text, match.start()),
                )
            )
    return findings


def extract_interesting_comments(js_text: str, source_file: str) -> list[CommentFinding]:
    """Extract comments that contain URLs, credentials, TODOs, or auth words."""

    findings: list[CommentFinding] = []
    interesting = ("http", "password", "token", "secret", "todo", "fixme", "admin", "debug")
    for match in COMMENT_PATTERN.finditer(js_text):
        text = " ".join(match.group(0).split())
        if not any(token in text.lower() for token in interesting):
            continue
        findings.append(CommentFinding(text=text[:240], source_file=source_file, line=_line_number(js_text, match.start())))
    return findings


def endpoint_to_path(endpoint: str, base_url: str) -> str | None:
    """Convert an endpoint or URL into a path suitable for directory discovery."""

    parsed = urlparse(urljoin(base_url, endpoint))
    if not parsed.path or parsed.path == "/":
        return None
    return parsed.path


def analyze_javascript(
    target: str,
    timeout: float = 5.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> dict[str, Any]:
    """Fetch a page and linked JS files, then extract endpoints and secrets."""

    base_url = normalize_url(target)
    try:
        html = _request_text(base_url, timeout, proxies, verify, scope_checker)
    except (requests.RequestException, ScopeError, RuntimeError) as exc:
        return {
            "target": base_url,
            "scripts": [],
            "endpoints": [],
            "secrets": [],
            "comments": [],
            "discovery_paths": [],
            "errors": [{"url": base_url, "error": str(exc)}],
            "source": "ACTIVE",
        }
    script_urls = extract_script_sources(html, base_url)

    scripts: list[ScriptSource] = [ScriptSource(url) for url in script_urls]
    endpoints: list[EndpointFinding] = []
    secrets: list[SecretFinding] = []
    comments: list[CommentFinding] = []
    errors: list[dict[str, str]] = []

    for script_url in script_urls:
        try:
            js_text = _request_text(script_url, timeout, proxies, verify, scope_checker)
        except (requests.RequestException, ScopeError, RuntimeError) as exc:
            errors.append({"url": script_url, "error": str(exc)})
            continue
        endpoints.extend(extract_endpoints(js_text, script_url))
        secrets.extend(extract_secrets(js_text, script_url))
        comments.extend(extract_interesting_comments(js_text, script_url))

    discovery_paths = sorted(
        {
            path
            for endpoint in endpoints
            for path in [endpoint_to_path(endpoint.endpoint, base_url)]
            if path
        }
    )

    return {
        "target": base_url,
        "scripts": [asdict(item) for item in scripts],
        "endpoints": [asdict(item) for item in endpoints],
        "secrets": [asdict(item) for item in secrets],
        "comments": [asdict(item) for item in comments],
        "discovery_paths": discovery_paths,
        "errors": errors,
        "source": "ACTIVE",
    }
