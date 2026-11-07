"""Authentication surface checks for authorized testing."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from html.parser import HTMLParser
import base64
import json
import time
from typing import Any
from urllib.parse import urljoin

import requests

from core.http_intel import normalize_url
from utils.scope_checker import ScopeChecker, ScopeError


LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "session")
JWT_COOKIE_HINTS = ("token", "jwt", "id_token", "access")


@dataclass(frozen=True)
class LoginForm:
    """A detected login-like HTML form."""

    action: str
    method: str
    username_field: str | None
    password_field: str | None
    input_names: tuple[str, ...]
    source: str = "ACTIVE"


@dataclass(frozen=True)
class RateLimitResult:
    """Small dummy login probe result."""

    action: str
    attempted: bool
    requests_sent: int
    rate_limited: bool
    statuses: tuple[int, ...]
    evidence: str
    source: str = "ACTIVE"


@dataclass(frozen=True)
class JWTAnalysis:
    """Decoded JWT metadata."""

    location: str
    alg: str | None
    expires_at: int | None
    expired: bool | None
    alg_none: bool
    decode_error: str | None = None
    source: str = "ACTIVE"


@dataclass(frozen=True)
class CookieFinding:
    """Session cookie flag finding."""

    name: str
    secure: bool
    httponly: bool
    samesite: str | None
    issues: tuple[str, ...]
    source: str = "ACTIVE"


class FormParser(HTMLParser):
    """Extract forms and input names from HTML."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "form":
            self._current = {
                "action": urljoin(self.base_url, attrs_dict.get("action", "")),
                "method": attrs_dict.get("method", "GET").upper() or "GET",
                "inputs": [],
            }
        elif tag.lower() == "input" and self._current is not None:
            self._current["inputs"].append(
                {
                    "name": attrs_dict.get("name", ""),
                    "type": attrs_dict.get("type", "text").lower(),
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def _request(
    method: str,
    url: str,
    timeout: float,
    proxies: dict[str, str] | None,
    verify: bool | str,
    scope_checker: ScopeChecker | None,
    data: dict[str, str] | None = None,
) -> requests.Response:
    if scope_checker:
        scope_checker.require_in_scope(url, "authentication testing request")
    kwargs: dict[str, Any] = {
        "timeout": timeout,
        "allow_redirects": True,
        "headers": {"User-Agent": "MiniReconAuthTester/3.0"},
        "proxies": proxies,
        "verify": verify,
    }
    if method.upper() == "GET":
        kwargs["params"] = data
    else:
        kwargs["data"] = data
    return requests.request(method, url, **kwargs)


def detect_login_forms(html: str, base_url: str) -> list[LoginForm]:
    """Detect login-like forms from HTML."""

    parser = FormParser(base_url)
    parser.feed(html)
    forms: list[LoginForm] = []
    for form in parser.forms:
        inputs = form.get("inputs", [])
        input_names = tuple(item.get("name", "") for item in inputs if item.get("name"))
        password_field = next((item.get("name") for item in inputs if item.get("type") == "password" and item.get("name")), None)
        username_field = next(
            (
                item.get("name")
                for item in inputs
                if item.get("name")
                and any(hint in item.get("name", "").lower() for hint in ("user", "email", "login", "name"))
            ),
            None,
        )
        action = str(form.get("action", ""))
        looks_like_login = bool(password_field) or any(hint in action.lower() for hint in LOGIN_HINTS)
        if not looks_like_login:
            continue
        forms.append(
            LoginForm(
                action=action,
                method=str(form.get("method", "GET")).upper(),
                username_field=username_field,
                password_field=password_field,
                input_names=input_names,
            )
        )
    return forms


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def decode_jwt(token: str, location: str = "unknown", now: int | None = None) -> JWTAnalysis:
    """Decode JWT header/payload without verifying signature."""

    parts = token.split(".")
    if len(parts) != 3:
        return JWTAnalysis(location, None, None, None, False, "not a JWT")
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return JWTAnalysis(location, None, None, None, False, str(exc))
    alg = header.get("alg")
    exp = payload.get("exp")
    expired = None
    if isinstance(exp, int):
        expired = exp < int(now if now is not None else time.time())
    return JWTAnalysis(location, alg, exp if isinstance(exp, int) else None, expired, str(alg).lower() == "none")


def analyze_session_cookies(cookies: requests.cookies.RequestsCookieJar) -> list[CookieFinding]:
    """Check common session cookie flags."""

    findings: list[CookieFinding] = []
    for cookie in cookies:
        name_lower = cookie.name.lower()
        is_sessionish = any(token in name_lower for token in ("session", "sid", "auth", "token", "jwt"))
        if not is_sessionish:
            continue
        rest = {key.lower(): value for key, value in cookie._rest.items()}
        httponly = "httponly" in rest
        samesite = rest.get("samesite")
        issues: list[str] = []
        if not cookie.secure:
            issues.append("missing Secure")
        if not httponly:
            issues.append("missing HttpOnly")
        if not samesite:
            issues.append("missing SameSite")
        findings.append(CookieFinding(cookie.name, cookie.secure, httponly, samesite, tuple(issues)))
    return findings


def analyze_jwts_from_cookies(cookies: requests.cookies.RequestsCookieJar) -> list[JWTAnalysis]:
    """Decode JWT-looking cookie values."""

    analyses: list[JWTAnalysis] = []
    for cookie in cookies:
        value = cookie.value
        if value.count(".") == 2 or any(hint in cookie.name.lower() for hint in JWT_COOKIE_HINTS):
            analysis = decode_jwt(value, location=f"cookie:{cookie.name}")
            if analysis.decode_error != "not a JWT":
                analyses.append(analysis)
    return analyses


def test_rate_limiting(
    form: LoginForm,
    timeout: float,
    proxies: dict[str, str] | None,
    verify: bool | str,
    scope_checker: ScopeChecker | None,
    attempts: int = 3,
) -> RateLimitResult:
    """Send a small number of dummy login attempts and look for throttling."""

    if not form.username_field or not form.password_field or form.method not in {"POST", "GET"}:
        return RateLimitResult(form.action, False, 0, False, (), "form lacks username/password fields or supported method")

    statuses: list[int] = []
    has_retry_after = False
    lockout_detected = False
    lockout_keywords = ("too many requests", "rate limit", "account locked", "try again in", "throttled", "exceeded attempt")
    data = {name: "minirecon-test" for name in form.input_names}
    data[form.username_field] = "minirecon-test"
    data[form.password_field] = "not-a-real-password"
    for _ in range(attempts):
        try:
            response = _request(form.method, form.action, timeout, proxies, verify, scope_checker, data=data)
        except (requests.RequestException, ScopeError) as exc:
            return RateLimitResult(form.action, True, len(statuses), False, tuple(statuses), str(exc))
        statuses.append(response.status_code)
        if "retry-after" in {k.lower() for k in response.headers}:
            has_retry_after = True
        body_lower = response.text[:2000].lower()
        if any(kw in body_lower for kw in lockout_keywords):
            lockout_detected = True

    # True rate-limiting / lockout is 429, a Retry-After header, or a status transition with lockout text
    # 401 Unauthorized alone on bad credentials is NOT rate limiting
    rate_limited = (
        any(status == 429 for status in statuses)
        or has_retry_after
        or (lockout_detected and any(status in {403, 429} for status in statuses))
        or (len(statuses) >= 2 and statuses[0] in {200, 401} and statuses[-1] in {403, 429} and lockout_detected)
    )
    if any(status == 429 for status in statuses):
        evidence = "HTTP 429 (Too Many Requests) returned by authentication endpoint"
    elif has_retry_after:
        evidence = "Retry-After response header observed on authentication endpoint"
    elif lockout_detected:
        evidence = "Lockout/rate-limit messaging detected in response body"
    else:
        evidence = "no rate-limit or lockout response observed in bounded 3-probe test (standard credential check)"
    return RateLimitResult(form.action, True, len(statuses), rate_limited, tuple(statuses), evidence)


def run_auth_tests(
    target: str,
    timeout: float = 5.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> dict[str, Any]:
    """Run authentication surface checks."""

    url = normalize_url(target)
    try:
        response = _request("GET", url, timeout, proxies, verify, scope_checker)
    except (requests.RequestException, ScopeError) as exc:
        return {
            "target": url,
            "login_forms": [],
            "rate_limit_tests": [],
            "jwt_analysis": [],
            "session_cookie_flags": [],
            "errors": [{"url": url, "error": str(exc)}],
            "source": "ACTIVE",
        }

    forms = detect_login_forms(response.text, response.url)
    rate_tests = [
        test_rate_limiting(form, timeout, proxies, verify, scope_checker)
        for form in forms[:3]
    ]
    return {
        "target": url,
        "login_forms": [asdict(item) for item in forms],
        "rate_limit_tests": [asdict(item) for item in rate_tests],
        "jwt_analysis": [asdict(item) for item in analyze_jwts_from_cookies(response.cookies)],
        "session_cookie_flags": [asdict(item) for item in analyze_session_cookies(response.cookies)],
        "errors": [],
        "source": "ACTIVE",
    }
