"""Scope enforcement for authorized testing."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a target or URL is outside the configured scope."""


@dataclass
class ScopeChecker:
    """Validate hosts and URLs against an allow-list of domains."""

    scopes: list[str] = field(default_factory=list)
    blocked_attempts: list[dict[str, str]] = field(default_factory=list)

    @classmethod
    def from_csv(cls, scope_csv: str | None) -> "ScopeChecker | None":
        if not scope_csv:
            return None
        scopes = [item.strip().lower().lstrip("*.") for item in scope_csv.split(",") if item.strip()]
        return cls(scopes=scopes)

    def normalize_host(self, value: str) -> str:
        text = value.strip().lower()
        if "://" in text:
            parsed = urlparse(text)
            text = parsed.hostname or ""
        else:
            text = text.split("/", 1)[0].split(":", 1)[0]
        return text.strip(".").lstrip("*.")

    def is_in_scope(self, value: str) -> bool:
        if not self.scopes:
            return True
        host = self.normalize_host(value)
        return any(host == scope or host.endswith(f".{scope}") for scope in self.scopes)

    def require_in_scope(self, value: str, reason: str = "request") -> None:
        if self.is_in_scope(value):
            return
        host = self.normalize_host(value)
        self.blocked_attempts.append({"target": value, "host": host, "reason": reason})
        raise ScopeError(f"Blocked out-of-scope {reason}: {value}")

    def report(self) -> list[dict[str, str]]:
        return list(self.blocked_attempts)
