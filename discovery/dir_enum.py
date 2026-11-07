"""Threaded directory and path discovery module.

Use only against targets you own or have explicit permission to test.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urljoin, urlparse
import uuid

import requests
from rich.console import Console

from utils.scope_checker import ScopeChecker, ScopeError


REPORT_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403}
DEFAULT_WORDLIST = Path(__file__).resolve().parents[1] / "wordlists" / "dirs.txt"
HIGH_RISK_PATHS = {"/backup", "/db", "/admin", "/config", "/.env", "/phpmyadmin", "/wp-admin"}
HIGH_RISK_EXTENSIONS = (".zip", ".sql", ".bak", ".log", ".env")
console = Console()


@dataclass(frozen=True)
class DirectoryFinding:
    """A discovered path that returned a reportable HTTP status."""

    path: str
    url: str
    final_url: str
    status_code: int
    reason: str
    risk_level: str
    note: str
    source: str = "ACTIVE"


def load_words(wordlist_path: str | Path = DEFAULT_WORDLIST) -> list[str]:
    """Load directory/path candidates from a wordlist file."""

    path = Path(wordlist_path)
    if not path.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")

    words: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        word = raw_line.strip()
        if not word or word.startswith("#"):
            continue
        words.append(word.lstrip("/"))
    return words


def normalize_base_url(target: str) -> str:
    """Ensure the target has a URL scheme and a trailing slash."""

    target = target.strip()
    if not target:
        raise ValueError("Target URL cannot be empty")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    scheme, rest = target.split("://", 1)
    if rest.startswith("*."):
        target = f"{scheme}://{rest[2:]}"
    return target.rstrip("/") + "/"


def build_url(base_url: str, word: str) -> str:
    """Join a target base URL and a path candidate."""

    return urljoin(base_url, word.lstrip("/"))


def is_recursive_seed(finding: DirectoryFinding) -> bool:
    """Return True when a finding can sensibly be scanned as a directory."""

    path = finding.path.rstrip("/")
    if not path or "." in path.rsplit("/", 1)[-1]:
        return False
    return finding.status_code in {200, 301, 302, 307, 308}


def classify_path(path: str, status_code: int = 200) -> tuple[str, str]:
    """Classify discovered paths for quick risk triage."""

    lowered = path.lower()
    if status_code in {401, 403}:
        if lowered in HIGH_RISK_PATHS:
            return "HIGH", f"PROTECTED SENSITIVE PATH ({status_code})"
        return "MEDIUM", f"RESTRICTED ACCESS ({status_code})"
    if lowered in HIGH_RISK_PATHS:
        if lowered == "/admin":
            return "HIGH", "ADMIN PANEL LIKELY"
        return "HIGH", "HIGH RISK PATH"
    if lowered.endswith(HIGH_RISK_EXTENSIONS):
        return "HIGH", "SENSITIVE FILE LIKELY"
    return "LOW", ""


def detect_soft_404_baseline(
    base_url: str,
    timeout: float = 5.0,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> tuple[int | None, str | None]:
    """Request a random non-existent UUID path to measure soft-404 behavior."""

    test_path = f"minirecon_probe_{uuid.uuid4().hex[:12]}"
    test_url = build_url(base_url, test_path)
    try:
        if scope_checker:
            scope_checker.require_in_scope(test_url, "soft-404 calibration")
        response = requests.get(
            test_url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "MiniReconDirEnum/3.0"},
            proxies=proxies,
            verify=verify,
        )
        if response.status_code == 200:
            return len(response.content), None
        if response.status_code in {301, 302, 307, 308}:
            location = response.headers.get("Location", "")
            return None, location
    except (requests.RequestException, ScopeError):
        pass
    return None, None


def check_path(
    base_url: str,
    word: str,
    timeout: float = 5.0,
    retries: int = 1,
    user_agent_provider: Callable[[], str] | None = None,
    delay_callback: Callable[[], None] | None = None,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
    soft_404_length: int | None = None,
    catchall_redirect: str | None = None,
) -> DirectoryFinding | None:
    """Request one candidate path and return it if the status is interesting."""

    candidate = word.lstrip("/")
    url = build_url(base_url, candidate)

    last_error: requests.RequestException | None = None
    for _ in range(retries + 1):
        if delay_callback:
            delay_callback()
        try:
            if scope_checker:
                scope_checker.require_in_scope(url, "directory discovery request")
            # Don't follow redirects blindly to avoid soft-404 loops to home page
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": user_agent_provider() if user_agent_provider else "MiniReconDirEnum/3.0"},
                proxies=proxies,
                verify=verify,
            )
        except ScopeError:
            return None
        except requests.RequestException as exc:
            last_error = exc
            continue

        status = response.status_code
        if status in REPORT_STATUSES:
            location = response.headers.get("Location")
            final_url = urljoin(url, location) if location else url

            # Filter out soft-404: 200 OK with identical content length to non-existent probe
            if status == 200 and soft_404_length is not None:
                if abs(len(response.content) - soft_404_length) <= 32:
                    return None

            # Filter out catch-all redirects (e.g. redirecting every bad path to root / or home)
            if status in {301, 302, 307, 308} and location:
                parsed_loc = urlparse(final_url)
                if catchall_redirect and (final_url == catchall_redirect or location == catchall_redirect):
                    return None
                if parsed_loc.path in {"", "/"} and urlparse(url).path not in {"", "/"}:
                    return None

            risk_level, note = classify_path(f"/{candidate}", status_code=status)
            return DirectoryFinding(
                path=f"/{candidate}",
                url=url,
                final_url=final_url,
                status_code=status,
                reason=response.reason,
                risk_level=risk_level,
                note=note,
                source="ACTIVE",
            )
        return None

    if last_error:
        return None
    return None


def enumerate_directories(
    target: str,
    wordlist_path: str | Path = DEFAULT_WORDLIST,
    extra_paths: Iterable[str] | None = None,
    threads: int = 20,
    timeout: float = 5.0,
    retries: int = 1,
    user_agent_provider: Callable[[], str] | None = None,
    delay_callback: Callable[[], None] | None = None,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
    recursive: bool = False,
    recursive_depth: int = 2,
) -> list[DirectoryFinding]:
    """Run threaded directory discovery against a target with soft-404 calibration."""

    base_url = normalize_base_url(target)
    words = load_words(wordlist_path)
    robots_paths = sorted({path.strip() for path in (extra_paths or []) if path and path.strip()})
    robots_words = [path.lstrip("/") for path in robots_paths]
    words = sorted(set(words + robots_words))
    findings: list[DirectoryFinding] = []
    robots_path_set = {f"/{word.lstrip('/')}" for word in robots_words}

    # Calibrate soft-404 baseline before scanning
    soft_404_len, catchall_redirect = detect_soft_404_baseline(
        base_url,
        timeout=timeout,
        proxies=proxies,
        verify=verify,
        scope_checker=scope_checker,
    )

    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        future_to_word = {
            executor.submit(
                check_path,
                base_url,
                word,
                timeout,
                retries,
                user_agent_provider,
                delay_callback,
                proxies,
                verify,
                scope_checker,
                soft_404_len,
                catchall_redirect,
            ): word
            for word in words
        }
        for future in as_completed(future_to_word):
            finding = future.result()
            if finding:
                if finding.path in robots_path_set:
                    finding = DirectoryFinding(
                        path=finding.path,
                        url=finding.url,
                        final_url=finding.final_url,
                        status_code=finding.status_code,
                        reason=finding.reason,
                        risk_level=finding.risk_level,
                        note="Discovered in robots.txt" if not finding.note else f"{finding.note}; Discovered in robots.txt",
                        source=finding.source,
                    )
                findings.append(finding)

    found_paths = {finding.path for finding in findings}
    for path in robots_paths:
        normalized_path = path if path.startswith("/") else f"/{path}"
        if normalized_path in found_paths:
            continue
        findings.append(
            DirectoryFinding(
                path=normalized_path,
                url=build_url(base_url, normalized_path),
                final_url=build_url(base_url, normalized_path),
                status_code=0,
                reason="robots.txt",
                risk_level="LOW",
                note="Discovered in robots.txt",
                source="PASSIVE",
            )
        )

    if recursive:
        findings = recursive_enumerate_directories(
            base_url,
            words,
            findings,
            threads=threads,
            timeout=timeout,
            retries=retries,
            user_agent_provider=user_agent_provider,
            delay_callback=delay_callback,
            proxies=proxies,
            verify=verify,
            scope_checker=scope_checker,
            max_depth=max(1, min(4, recursive_depth)),
            soft_404_length=soft_404_len,
            catchall_redirect=catchall_redirect,
        )

    return sorted(findings, key=lambda item: item.path)


def recursive_enumerate_directories(
    root_base_url: str,
    words: list[str],
    initial_findings: list[DirectoryFinding],
    threads: int = 20,
    timeout: float = 5.0,
    retries: int = 1,
    user_agent_provider: Callable[[], str] | None = None,
    delay_callback: Callable[[], None] | None = None,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
    max_depth: int = 2,
    soft_404_length: int | None = None,
    catchall_redirect: str | None = None,
) -> list[DirectoryFinding]:
    """Recursively scan discovered directory-like paths."""

    all_findings = list(initial_findings)
    seen_paths = {finding.path for finding in all_findings}
    queue: list[tuple[str, int]] = [
        (finding.path.rstrip("/") + "/", 1)
        for finding in initial_findings
        if is_recursive_seed(finding)
    ]

    while queue:
        parent_path, depth = queue.pop(0)
        if depth > max_depth:
            continue
        console.print(f"[cyan][*] Recursive directory scan depth {depth}: {parent_path}[/cyan]")
        base_url = build_url(root_base_url, parent_path).rstrip("/") + "/"
        child_findings: list[DirectoryFinding] = []
        with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
            future_to_word = {
                executor.submit(
                    check_path,
                    base_url,
                    word,
                    timeout,
                    retries,
                    user_agent_provider,
                    delay_callback,
                    proxies,
                    verify,
                    scope_checker,
                    soft_404_length,
                    catchall_redirect,
                ): word
                for word in words
            }
            for future in as_completed(future_to_word):
                finding = future.result()
                if not finding:
                    continue
                combined_path = "/" + parent_path.strip("/") + finding.path
                if combined_path in seen_paths:
                    continue
                seen_paths.add(combined_path)
                recursive_finding = DirectoryFinding(
                    path=combined_path,
                    url=finding.url,
                    final_url=finding.final_url,
                    status_code=finding.status_code,
                    reason=finding.reason,
                    risk_level=finding.risk_level,
                    note=finding.note if finding.note else f"Recursive depth {depth}",
                    source=finding.source,
                )
                child_findings.append(recursive_finding)
                if is_recursive_seed(recursive_finding) and depth < max_depth:
                    queue.append((combined_path.rstrip("/") + "/", depth + 1))
        all_findings.extend(child_findings)

    return all_findings


def print_findings(findings: Iterable[DirectoryFinding]) -> None:
    """Print directory findings in a compact terminal-friendly format."""

    for finding in findings:
        redirect = ""
        if finding.final_url != finding.url:
            redirect = f" -> redirects to {finding.final_url}"
        note = f" [{finding.note}]" if finding.note else ""
        style = "red bold" if finding.risk_level == "HIGH" else "green"
        console.print(f"{finding.path}{redirect} -> {finding.status_code} {finding.reason}{note}", style=style)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Threaded directory discovery")
    parser.add_argument("target", help="Target host or base URL")
    parser.add_argument("--wordlist", default=str(DEFAULT_WORDLIST), help="Path to directory wordlist")
    parser.add_argument("--threads", type=int, default=20, help="Number of worker threads")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds")
    parser.add_argument("--retries", type=int, default=1, help="Retries per path after request errors")
    parser.add_argument("--recursive", action="store_true", help="Recursively scan discovered directories")
    parser.add_argument("--recursive-depth", type=int, default=2, help="Recursive depth 1-4")
    args = parser.parse_args()

    results = enumerate_directories(
        args.target,
        wordlist_path=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        retries=args.retries,
        recursive=args.recursive,
        recursive_depth=args.recursive_depth,
    )
    print_findings(results)
