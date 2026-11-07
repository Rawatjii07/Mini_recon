"""Parameter-aware HTTP fuzzer.

Use only against targets you own or have explicit permission to test.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

import requests
from rich.console import Console
from rich.table import Table
from tqdm import tqdm

from bypass.waf_bypass import WAFDetection, detect_waf as detect_waf_response, generate_bypass_payloads, throttle_if_rate_limited
from utils.scope_checker import ScopeChecker, ScopeError


FUZZ_MARKER = "FUZZ"
DEFAULT_PAYLOADS = Path(__file__).resolve().parents[1] / "wordlists" / "payloads.txt"
console = Console()

WAF_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "x-amzn-requestid": "AWS WAF",
    "x-sucuri-id": "Sucuri",
    "mod_security": "ModSecurity",
}

SQLI_PATTERNS = ("' OR", "UNION", "--", "SELECT", "1=1")
XSS_PATTERNS = ("<script>", "onerror=", "<svg", "alert(")
LFI_PATTERNS = ("../", "etc/passwd", "%2f")
SSTI_PATTERNS = ("{{", "${", "7*7")


@dataclass(frozen=True)
class FuzzResult:
    """One parameter/payload attempt and the HTTP response details."""

    payload: str
    param: str
    url: str
    status_code: int | None
    response_length: int
    body_preview: str
    possible_vulnerability: bool
    reason: str
    attack_type: str
    risk_level: str
    baseline_length: int
    length_diff: int
    change_percent: float
    similarity_ratio: float


def load_payloads(payload_path: str | Path = DEFAULT_PAYLOADS) -> list[str]:
    """Load fuzz payloads from a wordlist file."""

    path = Path(payload_path)
    if not path.exists():
        raise FileNotFoundError(f"Payload wordlist not found: {path}")

    payloads: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        payload = raw_line.strip()
        if not payload or payload.startswith("#"):
            continue
        payloads.append(payload)
    return payloads


def ensure_url(target_url: str) -> str:
    """Validate a URL and add a simple fuzz parameter if no query exists."""

    target_url = target_url.strip()
    if not target_url.startswith(("http://", "https://")):
        raise ValueError("Target URL must include http:// or https://")
    scheme, rest = target_url.split("://", 1)
    if rest.startswith("*."):
        target_url = f"{scheme}://{rest[2:]}"

    parsed = urlparse(target_url)
    if parsed.query:
        return target_url
    return urlunparse(parsed._replace(query="fuzz=FUZZ"))


def extract_parameters(target_url: str) -> dict[str, str]:
    """Extract query parameters and baseline values from a URL."""

    parsed = urlparse(target_url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not params:
        return {"fuzz": FUZZ_MARKER}
    return params


def build_param_url(target_url: str, param: str, payload: str, url_encode: bool = True) -> str:
    """Build a URL where only one parameter is replaced by the payload."""

    parsed = urlparse(ensure_url(target_url))
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not params:
        params = {"fuzz": FUZZ_MARKER}

    value = quote(payload, safe="") if url_encode else payload
    params[param] = value
    query = urlencode(params, doseq=False, safe="%") if url_encode else "&".join(
        f"{key}={item}" for key, item in params.items()
    )
    return urlunparse(parsed._replace(query=query))


def build_polluted_param_url(target_url: str, param: str, payload: str, url_encode: bool = True) -> str:
    """Build a URL with a duplicate parameter for comparison testing."""

    parsed = urlparse(ensure_url(target_url))
    params = parse_qsl(parsed.query, keep_blank_values=True)
    value = quote(payload, safe="") if url_encode else payload
    pairs: list[tuple[str, str]] = []
    inserted = False
    for key, item in params:
        pairs.append((key, item))
        if key == param:
            pairs.append((key, value))
            inserted = True
    if not inserted:
        pairs.append((param, value))
    query = urlencode(pairs, doseq=True, safe="%") if url_encode else "&".join(f"{key}={item}" for key, item in pairs)
    return urlunparse(parsed._replace(query=query))


def baseline_url_for_param(target_url: str, param: str, baseline_payload: str = "1") -> str:
    """Build a baseline URL for one parameter while preserving other values."""

    parsed = urlparse(ensure_url(target_url))
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not params:
        params = {"fuzz": FUZZ_MARKER}

    if params.get(param) == FUZZ_MARKER:
        params[param] = baseline_payload
    query = urlencode(params, doseq=False)
    return urlunparse(parsed._replace(query=query))


def classify_payload(payload: str) -> str:
    """Classify a payload into a broad attack type."""

    checks = {
        "sqli": SQLI_PATTERNS,
        "xss": XSS_PATTERNS,
        "lfi": LFI_PATTERNS,
        "ssti": SSTI_PATTERNS,
    }
    lowered = payload.lower()
    for attack_type, patterns in checks.items():
        for pattern in patterns:
            if pattern.lower() in lowered:
                return attack_type
    return "unknown"


def mutate(payload: str, bypass_waf: bool = False) -> list[str]:
    """Return simple retry mutations for payloads that are blocked."""

    mutations = [
        payload,
        payload.replace("<script>", "<scr<script>ipt>"),
        payload.replace(" ", "%20"),
        payload.replace("'", "%27"),
        payload.upper(),
    ]
    if bypass_waf:
        mutations.extend(generate_bypass_payloads(payload))
    seen: set[str] = set()
    unique: list[str] = []
    for item in mutations:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def prioritize_payloads(payloads: list[str], param: str, value: str, path: str, body: str) -> list[str]:
    """Order payloads based on parameter context and baseline response body."""

    value_is_numeric = value.strip().lstrip("-").isdigit()
    body_has_html = "<html" in body.lower() or "<body" in body.lower() or "<form" in body.lower()
    path_suggests_file = "/file" in path.lower() or "/path" in path.lower()

    def score(payload: str) -> int:
        attack_type = classify_payload(payload)
        points = 0
        if value_is_numeric and attack_type == "sqli":
            points += 30
        if body_has_html and attack_type == "xss":
            points += 20
        if path_suggests_file and attack_type == "lfi":
            points += 20
        if attack_type != "unknown":
            points += 5
        return -points

    return sorted(payloads, key=score)


def preview_body(response: requests.Response, limit: int = 180) -> str:
    """Return a compact single-line body preview."""

    text = response.text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    return text[:limit]


def body_similarity_ratio(baseline_body: str, response_body: str) -> float:
    """Compare a fuzzed response body with the baseline body."""

    if not baseline_body and not response_body:
        return 1.0
    return SequenceMatcher(None, baseline_body, response_body).ratio()


def risk_from_similarity(similarity_ratio: float) -> str:
    """Convert a body similarity ratio into a risk label."""

    if similarity_ratio < 0.80:
        return "HIGH"
    if similarity_ratio < 0.93:
        return "MEDIUM"
    return "LOW"


def upgrade_risk(current: str, minimum: str) -> str:
    """Raise a risk label to at least the requested minimum level."""

    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    return minimum if order.get(current, 0) < order.get(minimum, 0) else current


def request_url(
    url: str,
    timeout: float = 5.0,
    retries: int = 1,
    user_agent_provider: Callable[[], str] | None = None,
    delay_callback: Callable[[], None] | None = None,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
    method: str = "GET",
    data: dict[str, str] | None = None,
) -> requests.Response:
    """Request one URL with optional user-agent rotation and request pacing."""

    last_error: requests.RequestException | None = None
    for _ in range(retries + 1):
        if delay_callback:
            delay_callback()
        try:
            if scope_checker:
                scope_checker.require_in_scope(url, "fuzzing request")
            headers = {"User-Agent": user_agent_provider() if user_agent_provider else "MiniReconFuzzer/3.0"}
            if method.upper() == "POST":
                response = requests.post(
                    url,
                    timeout=timeout,
                    allow_redirects=False,
                    headers=headers,
                    data=data or {},
                    proxies=proxies,
                    verify=verify,
                )
            else:
                response = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=False,
                    headers=headers,
                    proxies=proxies,
                    verify=verify,
                )
            throttle_if_rate_limited(response)
            return response
        except ScopeError as exc:
            raise RuntimeError(str(exc)) from exc
        except requests.RequestException as exc:
            last_error = exc
    raise RuntimeError(f"Request failed for {url}: {last_error}")


def detect_waf(
    target_url: str,
    timeout: float = 5.0,
    user_agent_provider: Callable[[], str] | None = None,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> WAFDetection:
    """Send one normal request and detect common WAF response headers."""

    url = ensure_url(target_url)
    try:
        if scope_checker:
            scope_checker.require_in_scope(url, "WAF detection request")
        headers = {"User-Agent": user_agent_provider() if user_agent_provider else "MiniReconFuzzer/3.0"}
        detection = detect_waf_response(url, timeout=timeout, headers=headers, proxies=proxies, verify=verify)
    except ScopeError as exc:
        return WAFDetection(False, None, str(exc), None)

    if detection.detected:
        console.print(f"[yellow][!] {detection.name} detected ({detection.reason}). Results may need manual validation.[/yellow]")
    return detection


def get_baseline(
    target_url: str,
    param: str,
    baseline_payload: str = "1",
    timeout: float = 5.0,
    retries: int = 1,
    user_agent_provider: Callable[[], str] | None = None,
    delay_callback: Callable[[], None] | None = None,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> tuple[FuzzResult, str]:
    """Fetch a baseline response for one parameter."""

    url = baseline_url_for_param(target_url, param, baseline_payload=baseline_payload)
    response = request_url(
        url,
        timeout=timeout,
        retries=retries,
        user_agent_provider=user_agent_provider,
        delay_callback=delay_callback,
        proxies=proxies,
        verify=verify,
        scope_checker=scope_checker,
    )
    result = FuzzResult(
        payload=baseline_payload,
        param=param,
        url=url,
        status_code=response.status_code,
        response_length=len(response.content),
        body_preview=preview_body(response),
        possible_vulnerability=False,
        reason="baseline",
        attack_type="baseline",
        risk_level="LOW",
        baseline_length=len(response.content),
        length_diff=0,
        change_percent=0.0,
        similarity_ratio=1.0,
    )
    return result, response.text


def risk_from_response(
    status_code: int | None,
    attack_type: str,
    similarity_ratio: float,
    change_percent: float,
) -> str:
    """Assign a simple per-result risk label."""

    risk = risk_from_similarity(similarity_ratio)
    if status_code == 500 and attack_type in {"sqli", "xss", "lfi", "ssti"}:
        risk = upgrade_risk(risk, "HIGH")
    if status_code in {403, 406, 429} and attack_type in {"sqli", "xss", "lfi", "ssti"}:
        risk = upgrade_risk(risk, "MEDIUM")
    if abs(change_percent) > 15:
        risk = upgrade_risk(risk, "MEDIUM")
    return risk


def result_priority(result: FuzzResult) -> tuple[int, int]:
    """Rank results so mutation retries do not hide blocked/anomalous behavior."""

    risk_score = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(result.risk_level, 0)
    return risk_score, 1 if result.possible_vulnerability else 0


def request_payload(
    target_url: str,
    param: str,
    payload: str,
    baseline_body: str,
    baseline_length: int,
    timeout: float = 5.0,
    retries: int = 1,
    url_encode: bool = True,
    unusual_ratio: float = 0.30,
    unusual_min_delta: int = 100,
    enable_mutation: bool = True,
    bypass_waf: bool = False,
    user_agent_provider: Callable[[], str] | None = None,
    delay_callback: Callable[[], None] | None = None,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> FuzzResult:
    """Send one payload against one parameter."""

    attack_type = classify_payload(payload)
    attempts = mutate(payload, bypass_waf=bypass_waf) if enable_mutation else ([payload] + generate_bypass_payloads(payload) if bypass_waf else [payload])
    best_result: FuzzResult | None = None

    for index, candidate in enumerate(attempts):
        use_pollution = bypass_waf and index > 0 and index % 4 == 0
        use_post = bypass_waf and index > 0 and index % 5 == 0
        # Avoid double-encoding when candidate is already percent-encoded or unicode-escaped
        candidate_url_encode = url_encode and not (candidate != payload and ("%" in candidate or "\\u" in candidate))
        url = build_polluted_param_url(target_url, param, candidate, url_encode=candidate_url_encode) if use_pollution else build_param_url(target_url, param, candidate, url_encode=candidate_url_encode)
        try:
            response = request_url(
                url,
                timeout=timeout,
                retries=retries,
                user_agent_provider=user_agent_provider,
                delay_callback=delay_callback,
                proxies=proxies,
                verify=verify,
                scope_checker=scope_checker,
                method="POST" if use_post else "GET",
                data={param: candidate} if use_post else None,
            )
            status_code = response.status_code
            length = len(response.content)
            body = preview_body(response)
            response_body = response.text
        except RuntimeError as exc:
            status_code = None
            length = 0
            body = str(exc)
            response_body = ""

        threshold = max(unusual_min_delta, int(baseline_length * unusual_ratio))
        unusual_length = abs(length - baseline_length) > threshold
        similarity_ratio = body_similarity_ratio(baseline_body, response_body)
        length_diff = length - baseline_length
        change_percent = (length_diff / baseline_length * 100) if baseline_length else 0.0
        risk_level = risk_from_response(status_code, attack_type, similarity_ratio, change_percent)
        possible = risk_level in {"MEDIUM", "HIGH", "CRITICAL"} or status_code == 500 or unusual_length or status_code in {403, 406}
        reasons: list[str] = []
        if status_code == 500:
            reasons.append("status 500")
        if status_code in {403, 406}:
            reasons.append("blocked response")
        if unusual_length:
            reasons.append("unusual length")
        if similarity_ratio < 0.93:
            reasons.append(f"body similarity {similarity_ratio:.2f}")
        if abs(change_percent) > 15:
            reasons.append(f"length changed {change_percent:.1f}%")
        if index > 0:
            reasons.append("mutation retry")
        if use_pollution:
            reasons.append("parameter pollution variant")
        if use_post:
            reasons.append("POST method variant")

        result = FuzzResult(
            payload=candidate,
            param=param,
            url=url,
            status_code=status_code,
            response_length=length,
            body_preview=body,
            possible_vulnerability=possible,
            reason=", ".join(reasons),
            attack_type=attack_type,
            risk_level=risk_level,
            baseline_length=baseline_length,
            length_diff=length_diff,
            change_percent=change_percent,
            similarity_ratio=similarity_ratio,
        )
        if best_result is None or result_priority(result) > result_priority(best_result):
            best_result = result
        # Only retry mutations if response indicated WAF blocking / rate limiting
        if status_code not in {403, 406, 429}:
            break

    return best_result if best_result else FuzzResult(
        payload=payload,
        param=param,
        url=target_url,
        status_code=None,
        response_length=0,
        body_preview="request failed",
        possible_vulnerability=False,
        reason="request failed",
        attack_type=attack_type,
        risk_level="LOW",
        baseline_length=baseline_length,
        length_diff=-baseline_length,
        change_percent=-100.0 if baseline_length else 0.0,
        similarity_ratio=0.0,
    )


def fuzz_url(
    target_url: str,
    payload_path: str | Path = DEFAULT_PAYLOADS,
    threads: int = 10,
    timeout: float = 5.0,
    retries: int = 1,
    baseline_payload: str = "1",
    url_encode: bool = True,
    enable_mutation: bool = True,
    user_agent_provider: Callable[[], str] | None = None,
    delay_callback: Callable[[], None] | None = None,
    bypass_waf: bool = False,
    proxies: dict[str, str] | None = None,
    verify: bool | str = True,
    scope_checker: ScopeChecker | None = None,
) -> tuple[list[FuzzResult], list[FuzzResult]]:
    """Fuzz every query parameter in a URL individually."""

    target_url = ensure_url(target_url)
    detect_waf(
        target_url,
        timeout=timeout,
        user_agent_provider=user_agent_provider,
        proxies=proxies,
        verify=verify,
        scope_checker=scope_checker,
    )
    payloads = load_payloads(payload_path)
    params = extract_parameters(target_url)
    parsed = urlparse(target_url)

    baselines: list[FuzzResult] = []
    results: list[FuzzResult] = []

    for param, value in params.items():
        baseline_value = baseline_payload if value == FUZZ_MARKER else value or baseline_payload
        try:
            baseline, baseline_body = get_baseline(
                target_url,
                param,
                baseline_payload=baseline_value,
                timeout=timeout,
                retries=retries,
                user_agent_provider=user_agent_provider,
                delay_callback=delay_callback,
                proxies=proxies,
                verify=verify,
                scope_checker=scope_checker,
            )
        except RuntimeError as exc:
            baselines.append(
                FuzzResult(
                    payload=baseline_value,
                    param=param,
                    url=baseline_url_for_param(target_url, param, baseline_payload=baseline_value),
                    status_code=None,
                    response_length=0,
                    body_preview=str(exc),
                    possible_vulnerability=False,
                    reason="baseline request failed",
                    attack_type="baseline",
                    risk_level="LOW",
                    baseline_length=0,
                    length_diff=0,
                    change_percent=0.0,
                    similarity_ratio=0.0,
                )
            )
            console.print(f"[yellow][!] Fuzzing skipped for parameter '{param}': {exc}[/yellow]")
            continue
        baselines.append(baseline)
        ordered_payloads = prioritize_payloads(payloads, param, value, parsed.path, baseline.body_preview)

        with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
            futures = [
                executor.submit(
                    request_payload,
                    target_url,
                    param,
                    payload,
                    baseline_body,
                    baseline.response_length,
                    timeout,
                    retries,
                    url_encode,
                    0.30,
                    100,
                    enable_mutation,
                    bypass_waf,
                    user_agent_provider,
                    delay_callback,
                    proxies,
                    verify,
                    scope_checker,
                )
                for payload in ordered_payloads
            ]
            for future in tqdm(
                as_completed(futures),
                total=len(futures),
                desc="Fuzzing payloads",
                colour="cyan",
            ):
                results.append(future.result())

    return baselines, sorted(results, key=lambda item: (item.param, item.payload))


def summarize_by_parameter(results: Iterable[FuzzResult]) -> dict[str, int]:
    """Count possible vulnerabilities by parameter name."""

    summary: dict[str, int] = {}
    for result in results:
        if result.possible_vulnerability:
            summary[result.param] = summary.get(result.param, 0) + 1
    return summary


def print_results(baselines: Iterable[FuzzResult], results: Iterable[FuzzResult]) -> None:
    """Print parameter-aware fuzzing results."""

    baseline_table = Table(title="Fuzzing Baselines")
    baseline_table.add_column("Parameter", style="cyan")
    baseline_table.add_column("Payload")
    baseline_table.add_column("Status")
    baseline_table.add_column("Length")
    for baseline in baselines:
        status = baseline.status_code if baseline.status_code is not None else "ERR"
        baseline_table.add_row(baseline.param, baseline.payload, str(status), str(baseline.response_length))
    console.print(baseline_table)

    table = Table(title="Fuzzing Results")
    table.add_column("Parameter", style="cyan")
    table.add_column("Payload")
    table.add_column("Status")
    table.add_column("Length")
    table.add_column("Length Diff")
    table.add_column("Change Percent")
    table.add_column("Risk Level")
    table.add_column("Attack Type")
    results_list = list(results)
    for result in results_list:
        status = result.status_code if result.status_code is not None else "ERR"
        risk = result.risk_level
        risk_style = "red bold" if risk in {"CRITICAL", "HIGH"} else "yellow" if risk == "MEDIUM" else "green"
        table.add_row(
            result.param,
            result.payload,
            str(status),
            str(result.response_length),
            str(result.length_diff),
            f"{result.change_percent:.1f}%",
            f"[{risk_style}]{risk}[/]",
            result.attack_type,
        )
    console.print(table)

    summary = summarize_by_parameter(results_list)
    if summary:
        for param, count in sorted(summary.items()):
            console.print(f"Parameter '{param}' -> {count} vulnerabilities found", style="yellow")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Parameter-aware HTTP fuzzer")
    parser.add_argument("target", help="Target URL, for example http://site/search?q=test&id=1")
    parser.add_argument("--payloads", default=str(DEFAULT_PAYLOADS), help="Path to payload wordlist")
    parser.add_argument("--threads", type=int, default=10, help="Number of worker threads per parameter")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds")
    parser.add_argument("--retries", type=int, default=1, help="Retries per payload after request errors")
    parser.add_argument("--baseline", default="1", help="Baseline value used for FUZZ placeholders")
    parser.add_argument("--no-urlencode", action="store_true", help="Insert payloads without URL encoding")
    parser.add_argument("--no-mutation", action="store_true", help="Disable mutation retries after 403")
    args = parser.parse_args()

    baseline_results, fuzz_results = fuzz_url(
        args.target,
        payload_path=args.payloads,
        threads=args.threads,
        timeout=args.timeout,
        retries=args.retries,
        baseline_payload=args.baseline,
        url_encode=not args.no_urlencode,
        enable_mutation=not args.no_mutation,
    )
    print_results(baseline_results, fuzz_results)
