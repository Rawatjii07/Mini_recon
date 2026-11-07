"""Threaded subdomain brute-force module using dnspython.

Use only against domains you own or have explicit permission to test.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
import threading
from typing import Callable, Iterable

import requests
from rich.console import Console

from utils.scope_checker import ScopeChecker, ScopeError

try:
    import dns.resolver
except ImportError:  # pragma: no cover - handled at runtime for friendly CLI errors
    dns = None  # type: ignore[assignment]


DEFAULT_WORDLIST = Path(__file__).resolve().parents[1] / "wordlists" / "subdomains.txt"
console = Console()


@dataclass(frozen=True)
class SubdomainFinding:
    """A DNS-resolving subdomain and its resolved IP addresses."""

    host: str
    addresses: tuple[str, ...]
    live: bool
    https: bool
    status_code: int | None
    keywords: tuple[str, ...]
    source: str = "PASSIVE"


def load_subdomains(wordlist_path: str | Path = DEFAULT_WORDLIST) -> list[str]:
    """Load subdomain labels from a wordlist file."""

    path = Path(wordlist_path)
    if not path.exists():
        raise FileNotFoundError(f"Subdomain wordlist not found: {path}")

    subdomains: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        item = raw_line.strip().lower()
        if not item or item.startswith("#"):
            continue
        subdomains.append(item.rstrip("."))
    return subdomains


def normalize_domain(domain: str) -> str:
    """Normalize a base domain into a DNS name without scheme or path."""

    domain = domain.strip().lower()
    if not domain:
        raise ValueError("Domain cannot be empty")
    domain = domain.removeprefix("http://").removeprefix("https://")
    domain = domain.split("/", 1)[0].split(":", 1)[0].strip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    if "*" in domain:
        raise ValueError("Wildcard domains must use the form *.example.com")
    if not domain:
        raise ValueError("Domain cannot be empty")
    return domain


def check_web_presence(
    host: str,
    timeout: float = 3.0,
    user_agent_provider: Callable[[], str] | None = None,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> tuple[bool, bool, int | None, tuple[str, ...]]:
    """Check whether a subdomain is live over HTTP/HTTPS and scan common keywords."""

    keywords = ("login", "admin", "dashboard", "portal")
    detected: set[str] = set()
    live = False
    https_ok = False
    status_code: int | None = None
    headers = {"User-Agent": user_agent_provider() if user_agent_provider else "MiniReconSubdomain/3.0"}

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            if scope_checker:
                scope_checker.require_in_scope(url, "subdomain web probe")
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers=headers,
                proxies=proxies,
                verify=verify,
            )
        except (requests.RequestException, ScopeError):
            continue

        live = True
        if status_code is None:
            status_code = response.status_code
        if scheme == "https":
            https_ok = True
        body = response.text.lower()
        for keyword in keywords:
            if keyword in body:
                detected.add(keyword)

    return live, https_ok, status_code, tuple(sorted(detected))


def resolve_host(
    host: str,
    timeout: float = 2.0,
    http_timeout: float = 3.0,
    user_agent_provider: Callable[[], str] | None = None,
    active_probe: bool = True,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
    wildcard_ips: set[str] | None = None,
) -> SubdomainFinding | None:
    """Resolve one hostname and return A/AAAA records if found (ignoring wildcard DNS)."""

    if dns is None:
        raise RuntimeError("dnspython is required. Install it with: pip install dnspython")

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    found_addresses: set[str] = set()
    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(host, record_type)
            found_addresses.update(answer.to_text() for answer in answers)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.exception.DNSException,
        ):
            continue

    if not found_addresses:
        return None

    # Filter out wildcard DNS catch-all IPs
    if wildcard_ips and found_addresses == wildcard_ips:
        return None

    addresses = tuple(sorted(found_addresses))
    live, https_ok, status_code, keywords = (False, False, None, ())
    source = "PASSIVE"
    if active_probe:
        live, https_ok, status_code, keywords = check_web_presence(
            host,
            timeout=http_timeout,
            user_agent_provider=user_agent_provider,
            proxies=proxies,
            verify=verify,
            scope_checker=scope_checker,
        )
        source = "ACTIVE"
    return SubdomainFinding(
        host=host,
        addresses=addresses,
        live=live,
        https=https_ok,
        status_code=status_code,
        keywords=keywords,
        source=source,
    )


def brute_force_subdomains(
    domain: str,
    wordlist_path: str | Path = DEFAULT_WORDLIST,
    threads: int = 20,
    timeout: float = 2.0,
    http_timeout: float = 3.0,
    user_agent_provider: Callable[[], str] | None = None,
    active_probe: bool = True,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> list[SubdomainFinding]:
    """Run threaded subdomain brute force against a base domain."""

    base_domain = normalize_domain(domain)
    labels = load_subdomains(wordlist_path)
    queue: Queue[str] = Queue()
    findings: list[SubdomainFinding] = []
    lock = threading.Lock()

    # Check for wildcard DNS resolution
    wildcard_ips: set[str] = set()
    if dns is not None:
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            resolver.timeout = timeout
            wildcard_host = f"mr-wildcard-check-99x.{base_domain}"
            for rt in ("A", "AAAA"):
                try:
                    ans = resolver.resolve(wildcard_host, rt)
                    wildcard_ips.update(a.to_text() for a in ans)
                except Exception:
                    pass
            if wildcard_ips:
                console.print(f"[yellow][!] Wildcard DNS detected for {base_domain}; filtering catch-all responses[/yellow]")
        except Exception:
            pass

    for label in labels:
        if label == "@":
            queue.put(base_domain)
        elif label.endswith(f".{base_domain}"):
            queue.put(label)
        else:
            queue.put(f"{label}.{base_domain}")

    def worker() -> None:
        while True:
            try:
                host = queue.get_nowait()
            except Empty:
                return
            try:
                finding = resolve_host(
                    host,
                    timeout=timeout,
                    http_timeout=http_timeout,
                    user_agent_provider=user_agent_provider,
                    active_probe=active_probe,
                    proxies=proxies,
                    verify=verify,
                    scope_checker=scope_checker,
                    wildcard_ips=wildcard_ips,
                )
                if finding:
                    with lock:
                        findings.append(finding)
            finally:
                queue.task_done()

    workers = [
        threading.Thread(target=worker, daemon=True)
        for _ in range(max(1, threads))
    ]
    for thread in workers:
        thread.start()
    queue.join()
    for thread in workers:
        thread.join()

    return sorted(findings, key=lambda item: item.host)


def print_findings(findings: Iterable[SubdomainFinding]) -> None:
    """Print subdomain findings in a compact terminal-friendly format."""

    for finding in findings:
        live = "LIVE" if finding.live else "DEAD"
        https = "HTTPS yes" if finding.https else "HTTPS no"
        keyword_text = f" | {', '.join(finding.keywords)} page detected" if finding.keywords else ""
        style = "green" if finding.live else "dim"
        console.print(f"{finding.host} -> {live} | {https}{keyword_text} | {', '.join(finding.addresses)}", style=style)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Threaded subdomain brute force")
    parser.add_argument("domain", help="Base domain, for example example.com")
    parser.add_argument("--wordlist", default=str(DEFAULT_WORDLIST), help="Path to subdomain wordlist")
    parser.add_argument("--threads", type=int, default=20, help="Number of worker threads")
    parser.add_argument("--timeout", type=float, default=2.0, help="DNS timeout in seconds")
    parser.add_argument("--http-timeout", type=float, default=3.0, help="HTTP timeout in seconds")
    args = parser.parse_args()

    results = brute_force_subdomains(
        args.domain,
        wordlist_path=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        http_timeout=args.http_timeout,
    )
    print_findings(results)
