# For ethical and educational use only.
# Only test systems you own or have explicit written permission to test.
# Never hardcode API keys - use .env file only.

"""MiniRecon v3.0 complete security platform."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from importlib import metadata, util
from pathlib import Path
import re
import socket
import sys
from typing import Any, Callable

from rich.console import Console
from rich.table import Table

from core import ai_module
from core.analyzer import calculate_risk, empty_scan_data, flag_anomalies, normalize_fuzz_result
from core.bounty import build_bounty_context, export_bounty_markdown
from core.cve_lookup import lookup_http_cves
from core.dns_intel import collect_dns_email_intel
from core.http_intel import check_http_intel, fetch_robots_paths
from core.learn import build_learn_mode
from core.stealth import apply_delay, random_user_agent
from core.suggestions import suggestions_for_scan
from core.tls_intel import analyze_tls_certificate, san_subdomains_for_target
from core.visualize import build_graph
from bypass.origin_discovery import discover_origin
from discovery.dir_enum import DEFAULT_WORDLIST as DIR_WORDLIST
from discovery.dir_enum import enumerate_directories, normalize_base_url
from fuzzing.fuzzer import DEFAULT_PAYLOADS, FUZZ_MARKER, fuzz_url, summarize_by_parameter
from intelligence.auth_tester import run_auth_tests
from intelligence.fingerprint import fingerprint_target
from intelligence.js_analyzer import analyze_javascript
from intelligence.wayback import collect_wayback_intel
from output.report import print_ai_block, print_banner, print_report, save_report
from recon.portscan import normalize_host, scan_ports
from recon.subdomain import DEFAULT_WORDLIST as SUBDOMAIN_WORDLIST
from recon.subdomain import brute_force_subdomains, normalize_domain
from utils.scope_checker import ScopeChecker
from utils.state_manager import load_state, load_targets, save_state
from utils.report_manager import save_auto_report, save_important_report
from verification.verifier import verify_findings


PROJECT_ROOT = Path(__file__).resolve().parent
VERSION = "3.0"


def target_slug(target: str) -> str:
    """Return a filename-safe identifier for a target."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", target.strip()).strip("._")
    return cleaned or "target"

AUTHORIZATION_REMINDER = (
    "MiniRecon is for use only on systems you own or have explicit written permission to test. "
    "Unauthorized use is illegal."
)
REQUIRED_DEPENDENCIES = (
    ("requests", "requests", "HTTP requests for web checks, fuzzing, verification, and passive APIs"),
    ("dnspython", "dns", "DNS resolution and email security records"),
    ("openai", "openai", "OpenAI-compatible NVIDIA NIM AI analysis"),
    ("python-dotenv", "dotenv", "Loading NVIDIA_API_KEY from .env"),
    ("rich", "rich", "Terminal tables and panels"),
    ("networkx", "networkx", "Scan graph data model"),
    ("matplotlib", "matplotlib", "Scan graph image rendering"),
    ("tqdm", "tqdm", "Progress bars for threaded modules"),
    ("jinja2", "jinja2", "HTML report rendering"),
)
REQUIRED_RUNTIME_PATHS = (
    PROJECT_ROOT / "wordlists" / "subdomains.txt",
    PROJECT_ROOT / "wordlists" / "dirs.txt",
    PROJECT_ROOT / "wordlists" / "payloads.txt",
)
MODULE_ORDER = [
    "recon",
    "http_intel",
    "tls_intel",
    "dns_intel",
    "wayback",
    "js_analysis",
    "origin_discovery",
    "discovery",
    "fuzzing",
    "verification",
    "auth_test",
    "fingerprint",
]
console = Console()


def dependency_version(package_name: str) -> str:
    """Return installed package version when available."""

    try:
        return metadata.version(package_name)
    except metadata.PackageNotFoundError:
        return "unknown"


def check_setup() -> bool:
    """Print a setup health check for dependencies and runtime files."""

    ok = True
    table = Table(title="MiniRecon Setup Check")
    table.add_column("Item", style="cyan")
    table.add_column("Status")
    table.add_column("Details")

    python_ok = sys.version_info >= (3, 10)
    ok = ok and python_ok
    table.add_row(
        "Python",
        "OK" if python_ok else "MISSING",
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} (requires 3.10+)",
    )

    for package, module, purpose in REQUIRED_DEPENDENCIES:
        installed = util.find_spec(module) is not None
        ok = ok and installed
        table.add_row(
            package,
            "OK" if installed else "MISSING",
            f"{dependency_version(package)} - {purpose}" if installed else f"Install with: pip install {package}",
        )

    for path in REQUIRED_RUNTIME_PATHS:
        exists = path.exists()
        ok = ok and exists
        table.add_row(path.name, "OK" if exists else "MISSING", str(path))

    console.print(table)
    if not ok:
        console.print("[yellow]Run: pip install -r requirements.txt[/yellow]")
    return ok


def resolve_ip(target: str) -> str | None:
    """Resolve target host to one IPv4 address for summary reporting."""

    host = normalize_host(target)
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def derive_fuzz_url(target: str) -> str:
    """Create a simple default fuzz URL when the user did not provide one."""

    if FUZZ_MARKER in target:
        return target
    base_url = normalize_base_url(target)
    return f"{base_url}?fuzz={FUZZ_MARKER}"


def derive_fuzz_url_from_scan(args: argparse.Namespace, scan_data: dict[str, Any]) -> str:
    """Prefer the observed HTTP final URL when building a default fuzz URL."""

    for item in scan_data.get("http_intel", []):
        final_url = item.get("final_url") or item.get("url")
        if final_url and not item.get("error"):
            return derive_fuzz_url(str(final_url))
    return derive_fuzz_url(args.target)


def dataclass_list(items: list[Any]) -> list[dict[str, Any]]:
    """Convert a list of dataclass objects into dictionaries."""

    return [asdict(item) for item in items]


def stealth_hooks(enabled: bool) -> tuple[Callable[[], str] | None, Callable[[], None] | None]:
    """Return request hooks for stealth/pacing mode."""

    if not enabled:
        return None, None
    return random_user_agent, lambda: apply_delay(verbose=False)


def maybe_print_ai(title: str, enabled: bool, content: str) -> None:
    """Print AI analysis only when the user enabled --ai."""

    if enabled:
        print_ai_block(title, content)


def record_ai(
    scan_data: dict[str, Any],
    key: str,
    title: str,
    enabled: bool,
    content_factory: Callable[[], str],
) -> None:
    """Call, print, and store AI analysis only when explicitly enabled."""

    if not enabled:
        return
    content = content_factory()
    scan_data.setdefault("ai_analyses", {})[key] = content
    maybe_print_ai(title, True, content)


def proxy_config(proxy: str | None) -> dict[str, str] | None:
    """Build a requests proxy mapping."""

    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


def verify_config(ca_cert: str | None) -> bool | str:
    """Return requests verify configuration."""

    return ca_cert if ca_cert else True


def recon_profile(args: argparse.Namespace) -> tuple[bool, bool]:
    """Return passive and active recon switches."""

    if args.passive and args.active:
        raise ValueError("Use either --passive or --active, not both.")
    if args.passive:
        return True, False
    if args.active:
        return False, True
    return True, True


def save_module_state(args: argparse.Namespace, module: str, report: dict[str, Any], scan_data: dict[str, Any]) -> None:
    """Persist module progress for --resume."""

    state_file = PROJECT_ROOT / "output" / f"{target_slug(args.target)}_state.json"
    save_state(args.target, args.mode, module, report, scan_data, state_file)


def run_recon(args: argparse.Namespace, scan_data: dict[str, Any]) -> dict[str, Any]:
    """Run passive DNS/subdomain and optional active port/web probing."""

    passive_enabled, active_enabled = recon_profile(args)
    console.print("[cyan][*] Running recon...[/cyan]")
    user_agent_provider, _ = stealth_hooks(args.stealth)
    proxies = proxy_config(args.proxy)
    verify = verify_config(args.ca_cert)
    scope_checker = ScopeChecker.from_csv(args.scope)

    result: dict[str, Any] = {"ip_address": None, "open_ports": [], "subdomains": []}
    if passive_enabled:
        result["ip_address"] = resolve_ip(args.target)

    if active_enabled:
        open_ports = scan_ports(
            args.target,
            port_range=args.port_range,
            ports=args.ports,
            threads=args.port_threads,
            timeout=args.port_timeout,
            scope_checker=scope_checker,
        )
        result["open_ports"] = dataclass_list(open_ports)
        scan_data["ports"] = result["open_ports"]

    try:
        domain = normalize_domain(args.target)
        subdomains = brute_force_subdomains(
            domain,
            wordlist_path=args.subdomain_wordlist,
            threads=args.subdomain_threads,
            timeout=args.dns_timeout,
            http_timeout=args.http_timeout,
            user_agent_provider=user_agent_provider,
            active_probe=active_enabled,
            proxies=proxies,
            verify=verify,
            scope_checker=scope_checker,
        )
    except RuntimeError as exc:
        console.print(f"[yellow][!] Subdomain scan skipped: {exc}[/yellow]")
        subdomains = []

    result["subdomains"] = dataclass_list(subdomains)
    scan_data["subdomains"] = result["subdomains"]
    if scope_checker:
        scan_data["scope_blocks"].extend(scope_checker.report())
    if result["open_ports"]:
        record_ai(scan_data, "ports", "Open Ports", args.ai, lambda: ai_module.ai_analyze_ports(result["open_ports"]))
    return result


def run_http_intel(args: argparse.Namespace, scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Run active HTTP intelligence checks."""

    console.print("[cyan][*] Running HTTP intelligence...[/cyan]")
    proxies = proxy_config(args.proxy)
    verify = verify_config(args.ca_cert)
    scope_checker = ScopeChecker.from_csv(args.scope)
    info = check_http_intel(args.target, timeout=args.http_timeout, proxies=proxies, verify=verify, scope_checker=scope_checker)
    info["source"] = "ACTIVE"
    findings = [info]
    scan_data["http_intel"] = findings
    scan_data["robots_paths"] = fetch_robots_paths(
        args.target,
        timeout=args.http_timeout,
        proxies=proxies,
        verify=verify,
        scope_checker=scope_checker,
        recursive=args.recursive,
        recursive_depth=args.recursive_depth,
    )
    scan_data["known_cves"] = lookup_http_cves(info, proxies=proxies, verify=verify)
    if scope_checker:
        scan_data["scope_blocks"].extend(scope_checker.report())
    record_ai(scan_data, "headers", "HTTP Headers", args.ai, lambda: ai_module.ai_analyze_headers(info))
    return findings


def run_tls_intel(args: argparse.Namespace, scan_data: dict[str, Any]) -> dict[str, Any]:
    """Run active TLS certificate checks and merge SAN subdomains into scan data."""

    console.print("[cyan][*] Running TLS certificate intelligence...[/cyan]")
    scope_checker = ScopeChecker.from_csv(args.scope)
    if scope_checker:
        scope_checker.require_in_scope(args.target, "TLS certificate check")
    tls_info = analyze_tls_certificate(args.target, timeout=args.http_timeout, ca_cert=args.ca_cert)
    tls_info["source"] = "ACTIVE"
    scan_data["tls_certificate"] = [tls_info]

    existing_hosts = {str(item.get("host", "")).lower() for item in scan_data.get("subdomains", [])}
    for host in san_subdomains_for_target(args.target, list(tls_info.get("subject_alt_names", []))):
        if host in existing_hosts:
            continue
        scan_data["subdomains"].append(
            {
                "host": host,
                "addresses": [],
                "live": False,
                "https": True,
                "status_code": None,
                "keywords": [],
                "source": "PASSIVE",
            }
        )
        existing_hosts.add(host)
    return tls_info


def run_dns_intel(args: argparse.Namespace, scan_data: dict[str, Any]) -> dict[str, Any]:
    """Run passive email and DNS intelligence checks."""

    console.print("[cyan][*] Running email and DNS intelligence...[/cyan]")
    dns_info = collect_dns_email_intel(args.target, timeout=args.dns_timeout)
    dns_info["source"] = "PASSIVE"
    scan_data["dns_intel"] = [dns_info]
    return dns_info


def run_discovery(args: argparse.Namespace, scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Run active directory discovery."""

    console.print("[cyan][*] Running directory discovery...[/cyan]")
    user_agent_provider, delay_callback = stealth_hooks(args.stealth)
    proxies = proxy_config(args.proxy)
    verify = verify_config(args.ca_cert)
    scope_checker = ScopeChecker.from_csv(args.scope)
    findings = enumerate_directories(
        args.target,
        wordlist_path=args.dir_wordlist,
        extra_paths=(
            list(scan_data.get("robots_paths", []))
            + list(scan_data.get("old_endpoints", []))
            + list(scan_data.get("js_discovery_paths", []))
        ),
        threads=args.dir_threads,
        timeout=args.http_timeout,
        retries=args.retries,
        user_agent_provider=user_agent_provider,
        delay_callback=delay_callback,
        proxies=proxies,
        verify=verify,
        scope_checker=scope_checker,
    )
    result = dataclass_list(findings)
    scan_data["directories"] = result
    if scope_checker:
        scan_data["scope_blocks"].extend(scope_checker.report())
    record_ai(scan_data, "directories", "Directory Results", args.ai, lambda: ai_module.ai_analyze_dirs(result))
    return result


def run_fuzzing(args: argparse.Namespace, scan_data: dict[str, Any]) -> dict[str, Any]:
    """Run active parameter-aware payload testing."""

    if args.fuzz_url:
        target_urls = [args.fuzz_url]
    else:
        target_urls = list(scan_data.get("fuzzer_targets", [])) or [derive_fuzz_url_from_scan(args, scan_data)]
    console.print(f"[cyan][*] Running parameter-aware fuzzer against {len(target_urls)} URL(s)[/cyan]")
    user_agent_provider, delay_callback = stealth_hooks(args.stealth)
    proxies = proxy_config(args.proxy)
    verify = verify_config(args.ca_cert)
    scope_checker = ScopeChecker.from_csv(args.scope)
    all_baselines = []
    all_results = []
    for target_url in target_urls:
        console.print(f"[cyan][*] Fuzz target: {target_url}[/cyan]")
        baselines, results = fuzz_url(
            target_url,
            payload_path=args.payload_wordlist,
            threads=args.fuzz_threads,
            timeout=args.http_timeout,
            retries=args.retries,
            baseline_payload=args.baseline,
            url_encode=not args.no_urlencode,
            enable_mutation=not args.no_mutation,
            user_agent_provider=user_agent_provider,
            delay_callback=delay_callback,
            bypass_waf=args.bypass_waf,
            proxies=proxies,
            verify=verify,
            scope_checker=scope_checker,
        )
        all_baselines.extend(baselines)
        all_results.extend(results)
    result_dicts = dataclass_list(all_results)
    for item in result_dicts:
        item["source"] = "ACTIVE"
    normalized = [normalize_fuzz_result(item) for item in result_dicts]
    anomalies = flag_anomalies(normalized)
    scan_data["fuzzing"] = result_dicts
    if scope_checker:
        scan_data["scope_blocks"].extend(scope_checker.report())
    record_ai(scan_data, "fuzzing", "Fuzzing Results", args.ai, lambda: ai_module.ai_analyze_fuzz(normalized))
    return {
        "target_url": target_urls[0],
        "target_urls": target_urls,
        "baselines": dataclass_list(all_baselines),
        "results": result_dicts,
        "anomalies": anomalies,
        "summary": summarize_by_parameter(all_results),
    }


def run_wayback(args: argparse.Namespace, scan_data: dict[str, Any]) -> dict[str, Any]:
    """Run passive Wayback Machine intelligence."""

    if not args.wayback:
        return {}
    console.print("[cyan][*] Running Wayback Machine intelligence...[/cyan]")
    scope_checker = ScopeChecker.from_csv(args.scope)
    try:
        result = collect_wayback_intel(
            args.target,
            PROJECT_ROOT / "output" / f"{target_slug(args.target)}_wayback_urls.txt",
            timeout=args.http_timeout,
            proxies=proxy_config(args.proxy),
            verify=verify_config(args.ca_cert),
            scope_checker=scope_checker,
        )
    except (RuntimeError, ValueError) as exc:
        result = {
            "domain": normalize_domain(args.target),
            "records": [],
            "urls": [],
            "params": [],
            "old_endpoints": [],
            "fuzzer_targets": [],
            "saved_path": "",
            "source": "PASSIVE",
            "error": str(exc),
        }
        console.print(f"[yellow][!] Wayback skipped: {exc}[/yellow]")
    scan_data["wayback"] = [result]
    scan_data["wayback_urls"] = result["urls"]
    scan_data["wayback_params"] = result["params"]
    scan_data["old_endpoints"] = result["old_endpoints"]
    scan_data["fuzzer_targets"] = result["fuzzer_targets"]
    if scope_checker:
        scan_data["scope_blocks"].extend(scope_checker.report())
    console.print(
        f"[green][+] Wayback found {len(result['urls'])} URLs, "
        f"{len(result['params'])} params, {len(result['old_endpoints'])} old endpoints[/green]"
    )
    return result


def run_js_analysis(args: argparse.Namespace, scan_data: dict[str, Any]) -> dict[str, Any]:
    """Run JavaScript analysis and feed discovered paths into discovery."""

    if not args.js_analysis:
        return {}
    console.print("[cyan][*] Running JavaScript analysis...[/cyan]")
    scope_checker = ScopeChecker.from_csv(args.scope)
    result = analyze_javascript(
        args.target,
        timeout=args.http_timeout,
        proxies=proxy_config(args.proxy),
        verify=verify_config(args.ca_cert),
        scope_checker=scope_checker,
    )
    scan_data["js_analysis"] = [result]
    scan_data["js_discovery_paths"] = result["discovery_paths"]
    if scope_checker:
        scan_data["scope_blocks"].extend(scope_checker.report())
    console.print(
        f"[green][+] JS analysis found {len(result['scripts'])} scripts, "
        f"{len(result['endpoints'])} endpoints, {len(result['secrets'])} possible secrets[/green]"
    )
    return result


def run_origin_discovery(args: argparse.Namespace, scan_data: dict[str, Any]) -> dict[str, Any]:
    """Run origin IP candidate discovery and fingerprint comparison."""

    if not args.find_origin:
        return {}
    console.print("[cyan][*] Running origin IP discovery...[/cyan]")
    _, active_enabled = recon_profile(args)
    scope_checker = ScopeChecker.from_csv(args.scope)
    result = discover_origin(
        args.target,
        timeout=args.http_timeout,
        proxies=proxy_config(args.proxy),
        verify=verify_config(args.ca_cert),
        scope_checker=scope_checker,
        active_probe=active_enabled,
    )
    scan_data["origin_discovery"] = [result]
    if scope_checker:
        scan_data["scope_blocks"].extend(scope_checker.report())
    console.print(
        f"[green][+] Origin discovery found {len(result.get('candidates', []))} candidates, "
        f"{len(result.get('matches', []))} fingerprint matches[/green]"
    )
    return result


def run_verification(args: argparse.Namespace, scan_data: dict[str, Any]) -> dict[str, Any]:
    """Run vulnerability verification after fuzzing completes."""

    if not args.verify:
        return {}
    console.print("[cyan][*] Running vulnerability verification...[/cyan]")
    scope_checker = ScopeChecker.from_csv(args.scope)
    result = verify_findings(
        args.target,
        list(scan_data.get("fuzzing", [])),
        timeout=max(args.http_timeout, 8.0),
        proxies=proxy_config(args.proxy),
        verify=verify_config(args.ca_cert),
        scope_checker=scope_checker,
    )
    scan_data["verification"] = [result]
    if scope_checker:
        scan_data["scope_blocks"].extend(scope_checker.report())
    console.print(f"[green][+] Verification completed with {result.get('confirmed_count', 0)} confirmed signal(s)[/green]")
    return result


def run_auth_test(args: argparse.Namespace, scan_data: dict[str, Any]) -> dict[str, Any]:
    """Run authentication testing."""

    if not args.auth_test:
        return {}
    console.print("[cyan][*] Running authentication checks...[/cyan]")
    scope_checker = ScopeChecker.from_csv(args.scope)
    result = run_auth_tests(
        args.target,
        timeout=args.http_timeout,
        proxies=proxy_config(args.proxy),
        verify=verify_config(args.ca_cert),
        scope_checker=scope_checker,
    )
    scan_data["auth_test"] = [result]
    if scope_checker:
        scan_data["scope_blocks"].extend(scope_checker.report())
    console.print(
        f"[green][+] Auth checks found {len(result.get('login_forms', []))} login form(s), "
        f"{len(result.get('jwt_analysis', []))} JWT-like token(s)[/green]"
    )
    return result


def run_fingerprint(args: argparse.Namespace, scan_data: dict[str, Any]) -> dict[str, Any]:
    """Run technology fingerprinting and merge CVE hints."""

    if not args.fingerprint:
        return {}
    console.print("[cyan][*] Running technology fingerprinting...[/cyan]")
    scope_checker = ScopeChecker.from_csv(args.scope)
    result = fingerprint_target(
        args.target,
        timeout=args.http_timeout,
        proxies=proxy_config(args.proxy),
        verify=verify_config(args.ca_cert),
        scope_checker=scope_checker,
    )
    scan_data["fingerprint"] = [result]
    existing = {item.get("id") for item in scan_data.get("known_cves", [])}
    for cve in result.get("cves", []):
        if cve.get("id") not in existing:
            scan_data["known_cves"].append(cve)
            existing.add(cve.get("id"))
    if scope_checker:
        scan_data["scope_blocks"].extend(scope_checker.report())
    console.print(
        f"[green][+] Fingerprinting found {len(result.get('technologies', []))} technologies, "
        f"{len(result.get('cves', []))} CVE hint(s)[/green]"
    )
    return result


def build_parser() -> argparse.ArgumentParser:
    """Build the main CLI parser."""

    epilog = f"""
Authorization reminder:
  {AUTHORIZATION_REMINDER}

Examples:
  python main.py --check-setup
  python main.py --target example.com --mode all --ports 80,443
  python main.py --target example.com --mode recon --passive
  python main.py --target example.com --mode all --scope example.com --proxy http://127.0.0.1:8080
  python main.py --target example.com --mode all --wayback --js-analysis --verify --learn
  python main.py --targets-file targets.txt --mode recon --resume
"""
    parser = argparse.ArgumentParser(
        description=f"MiniRecon v3.0 ethical security testing platform. {AUTHORIZATION_REMINDER}",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"MiniRecon v{VERSION}")
    parser.add_argument("--check-setup", action="store_true", help="Check Python version, dependencies, and required wordlists")
    parser.add_argument("--target", help="Target domain, host, base URL, or FUZZ URL")
    parser.add_argument("--targets-file", help="Read one target per line and scan each in sequence")
    parser.add_argument("--mode", choices=("recon", "discover", "fuzz", "all"), help="Module to run")
    parser.add_argument("--gui", action="store_true", help="Launch the Tkinter desktop GUI")
    parser.add_argument("--output", help="Save final report to .txt, .json, or .html")
    parser.add_argument("--save-report", action="store_true", help="Mark this scan report as important/protected")
    parser.add_argument("--ai", action="store_true", help="Enable NVIDIA NIM AI analyst if .env has NVIDIA_API_KEY")
    parser.add_argument("--visualize", action="store_true", help="Save and display output/scan_graph.png")
    parser.add_argument("--stealth", action="store_true", help="Enable request pacing and browser User-Agent rotation")

    parser.add_argument("--passive", action="store_true", help="Passive recon only; no direct target server contact")
    parser.add_argument("--active", action="store_true", help="Active recon only; direct scanning and probing")
    parser.add_argument("--recon-mode", default="all", choices=("all", "active", "passive"), help="Recon profile alias")
    parser.add_argument("--bypass-waf", action="store_true", help="Enable authorized WAF behavior testing payload variants")
    parser.add_argument("--wayback", action="store_true", help="Use Wayback CDX API to collect historical URLs and parameters")
    parser.add_argument("--js-analysis", action="store_true", help="Analyze linked JavaScript for endpoints, routes, and secret-like values")
    parser.add_argument("--find-origin", action="store_true", help="Collect origin IP candidates and compare HTTP fingerprints")
    parser.add_argument("--verify", action="store_true", help="Verify supported fuzzing findings and CORS behavior after fuzzing")
    parser.add_argument("--auth-test", action="store_true", help="Detect login forms, JWT issues, session cookie flags, and basic rate limiting")
    parser.add_argument("--fingerprint", action="store_true", help="Detect web technologies and map product/version hints to CVEs")
    parser.add_argument("--bounty-report", action="store_true", help="Generate HackerOne-style bounty context and remediation skeletons")
    parser.add_argument("--learn", action="store_true", help="Enable professional text-only learn mode in reports")
    parser.add_argument("--proxy", help="Route HTTP requests through a proxy, for example http://127.0.0.1:8080")
    parser.add_argument("--ca-cert", help="Custom CA certificate path for HTTPS requests")
    parser.add_argument("--scope", help="Comma-separated in-scope domains. Out-of-scope requests are blocked")
    parser.add_argument("--resume", action="store_true", help="Resume from output/scan_state.json where possible")

    parser.add_argument("--dir-wordlist", default=str(DIR_WORDLIST), help="Directory wordlist path")
    parser.add_argument("--payload-wordlist", default=str(DEFAULT_PAYLOADS), help="Payload wordlist path")
    parser.add_argument("--subdomain-wordlist", default=str(SUBDOMAIN_WORDLIST), help="Subdomain wordlist path")

    parser.add_argument("--fuzz-url", help="URL containing FUZZ or normal parameters. Overrides --target for fuzz mode")
    parser.add_argument("--baseline", default="1", help="Baseline value for FUZZ placeholders")
    parser.add_argument("--no-urlencode", action="store_true", help="Send fuzz payloads without URL encoding")
    parser.add_argument("--no-mutation", action="store_true", help="Disable mutation retries after blocked responses")

    parser.add_argument("--ports", help="Comma-separated ports for port scan, or 'all', for example 80,443")
    parser.add_argument("--range", dest="port_range", help="Port range for port scan, for example 1-1000")

    parser.add_argument("--dir-threads", type=int, default=20, help="Directory discovery threads")
    parser.add_argument("--recursive", action="store_true", help="Recursively scan discovered directories")
    parser.add_argument("--recursive-depth", type=int, default=2, help="Recursive directory depth 1-4")
    parser.add_argument("--fuzz-threads", type=int, default=10, help="Fuzzer threads per parameter")
    parser.add_argument("--subdomain-threads", type=int, default=20, help="Subdomain brute-force threads")
    parser.add_argument("--port-threads", type=int, default=100, help="Port scanner threads")

    parser.add_argument("--http-timeout", type=float, default=5.0, help="HTTP timeout in seconds")
    parser.add_argument("--dns-timeout", type=float, default=2.0, help="DNS timeout in seconds")
    parser.add_argument("--port-timeout", type=float, default=1.0, help="Socket timeout in seconds")
    parser.add_argument("--retries", type=int, default=1, help="HTTP retries after request errors")
    return parser


def normalize_recon_aliases(args: argparse.Namespace) -> None:
    """Apply --recon-mode aliases to existing --active/--passive switches."""

    if args.recon_mode == "active":
        args.active = True
        args.passive = False
    elif args.recon_mode == "passive":
        args.passive = True
        args.active = False
    args.recursive_depth = max(1, min(4, args.recursive_depth))


def resume_context(args: argparse.Namespace) -> tuple[list[str], dict[str, Any], dict[str, Any]]:
    """Return completed modules plus saved report/data for matching --resume state."""

    if not args.resume:
        return [], {}, {}
    state_file = PROJECT_ROOT / "output" / f"{target_slug(args.target)}_state.json"
    if not state_file.exists():
        state_file = PROJECT_ROOT / "output" / "scan_state.json"
    state = load_state(state_file)
    if state.get("target") != args.target or state.get("mode") != args.mode:
        return [], {}, {}
    last = state.get("last_completed_module")
    if last not in MODULE_ORDER:
        return [], {}, {}
    completed = MODULE_ORDER[: MODULE_ORDER.index(last) + 1]
    return completed, state.get("report", {}), state.get("scan_data", {})


def run_target(args: argparse.Namespace) -> dict[str, Any]:
    """Run the selected mode for one target."""

    completed_list, saved_report, saved_scan_data = resume_context(args)
    scan_data = saved_scan_data or empty_scan_data()
    scan_data.setdefault("scope_blocks", [])
    report: dict[str, Any] = saved_report or {"target": args.target, "mode": args.mode}
    completed = set(completed_list)

    passive_enabled, active_enabled = recon_profile(args)

    if args.mode in ("recon", "all"):
        if "recon" not in completed:
            report["recon"] = run_recon(args, scan_data)
            save_module_state(args, "recon", report, scan_data)
        if active_enabled and "http_intel" not in completed:
            report["http_intel"] = run_http_intel(args, scan_data)
            save_module_state(args, "http_intel", report, scan_data)
        if active_enabled and "tls_intel" not in completed:
            report["tls_certificate"] = run_tls_intel(args, scan_data)
            save_module_state(args, "tls_intel", report, scan_data)
        if passive_enabled and "dns_intel" not in completed:
            report["dns_intel"] = run_dns_intel(args, scan_data)
            save_module_state(args, "dns_intel", report, scan_data)
        report["known_cves"] = scan_data.get("known_cves", [])
        report.setdefault("recon", {})["subdomains"] = scan_data["subdomains"]

    if args.wayback and "wayback" not in completed:
        report["wayback"] = run_wayback(args, scan_data)
        save_module_state(args, "wayback", report, scan_data)

    if args.js_analysis and active_enabled and "js_analysis" not in completed:
        report["js_analysis"] = run_js_analysis(args, scan_data)
        save_module_state(args, "js_analysis", report, scan_data)

    if args.find_origin and "origin_discovery" not in completed:
        report["origin_discovery"] = run_origin_discovery(args, scan_data)
        save_module_state(args, "origin_discovery", report, scan_data)

    if args.mode in ("discover", "all") and active_enabled and "discovery" not in completed:
        report["directory_discovery"] = run_discovery(args, scan_data)
        save_module_state(args, "discovery", report, scan_data)

    if args.mode in ("fuzz", "all") and active_enabled and "fuzzing" not in completed:
        report["fuzzing"] = run_fuzzing(args, scan_data)
        save_module_state(args, "fuzzing", report, scan_data)

    if args.verify and args.mode in ("fuzz", "all") and active_enabled and "verification" not in completed:
        report["verification"] = run_verification(args, scan_data)
        save_module_state(args, "verification", report, scan_data)

    if args.auth_test and active_enabled and "auth_test" not in completed:
        report["auth_test"] = run_auth_test(args, scan_data)
        save_module_state(args, "auth_test", report, scan_data)

    if args.fingerprint and active_enabled and "fingerprint" not in completed:
        report["fingerprint"] = run_fingerprint(args, scan_data)
        report["known_cves"] = scan_data.get("known_cves", [])
        save_module_state(args, "fingerprint", report, scan_data)

    report["scan_data"] = scan_data
    report["risk"] = calculate_risk(scan_data)
    report["suggestions"] = suggestions_for_scan(scan_data)
    bounty_context = build_bounty_context(scan_data)
    scan_data["bounty_context"] = [bounty_context]
    report["bounty_context"] = bounty_context

    if args.learn:
        learn_mode = build_learn_mode(bounty_context, PROJECT_ROOT / "output" / "learn_progress.json")
        scan_data["learn_mode"] = [learn_mode]
        report["learn_mode"] = learn_mode

    if args.bounty_report:
        bounty_path = export_bounty_markdown(
            bounty_context,
            PROJECT_ROOT / "output" / f"{target_slug(args.target)}_bounty_report.md",
        )
        report["bounty_report"] = str(bounty_path)
        console.print(f"[green][+] Bounty report skeleton saved to {bounty_path}[/green]")

    if args.ai:
        final_ai = ai_module.ai_analyze_summary(scan_data)
        scan_data.setdefault("ai_analyses", {})["summary"] = final_ai
        report["ai_analyses"] = scan_data["ai_analyses"]
        print_ai_block("Final Report", final_ai)

    if args.visualize:
        graph_path = build_graph(
            scan_data,
            args.target,
            PROJECT_ROOT / "output" / f"{target_slug(args.target)}_scan_graph.png",
            show=True,
        )
        report["visualization"] = str(graph_path)
        console.print(f"[green][+] Visualization saved to {graph_path}[/green]")

    auto_report_path = save_auto_report(report, args.target, args.mode)
    report["auto_report"] = str(auto_report_path)
    print_report(report)
    console.print(f"\n[green][+] Auto report saved to {auto_report_path}[/green]")

    if args.save_report:
        saved_report_path = save_important_report(str(auto_report_path))
        report["saved_report"] = str(saved_report_path)
        console.print(f"[green][+] Important report saved to {saved_report_path}[/green]")

    if args.output:
        saved_path = save_report(report, args.output)
        console.print(f"\n[green][+] Report saved to {saved_path}[/green]")

    return report


def main() -> int:
    """CLI entry point."""

    parser = build_parser()
    args = parser.parse_args()
    normalize_recon_aliases(args)

    if args.check_setup:
        print_banner()
        console.print(f"[yellow]{AUTHORIZATION_REMINDER}[/yellow]")
        return 0 if check_setup() else 1

    if args.gui:
        from gui.app import launch

        launch()
        return 0

    print_banner()
    console.print(f"[yellow]{AUTHORIZATION_REMINDER}[/yellow]")
    if args.ai and not ai_module.ai_configured():
        console.print("[yellow][!] --ai enabled, but NVIDIA_API_KEY was not found in .env.[/yellow]")

    if not args.target and not args.targets_file:
        parser.error("one of --target or --targets-file is required")
    if not args.mode:
        parser.error("--mode is required unless --gui is used")

    try:
        targets = load_targets(args.targets_file) if args.targets_file else [args.target]
        for target in targets:
            args.target = target
            run_target(args)
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        console.print(f"[red bold][!] Error: {exc}[/red bold]")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
