"""Rich reporting helpers for the mini security platform."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.analyzer import format_flagged_result


console = Console()


def _serializable(value: Any) -> Any:
    """Convert dataclasses and nested values into JSON-serializable objects."""

    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return {key: _serializable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serializable(item) for item in value]
    return value


def print_banner() -> None:
    """Print a compact ASCII banner."""

    console.print(
        """
 __  __ _       _ ____                       
|  \\/  (_)_ __ (_)  _ \\ ___  ___ ___  _ __  
| |\\/| | | '_ \\| | |_) / _ \\/ __/ _ \\| '_ \\ 
| |  | | | | | | |  _ <  __/ (_| (_) | | | |
|_|  |_|_|_| |_|_|_| \\_\\___|\\___\\___/|_| |_|
""",
        style="cyan",
    )


def print_ai_block(title: str, content: str) -> None:
    """Print AI output in a distinct highlighted block."""

    console.print(Panel(content or "No AI output.", title=f"AI ANALYSIS - {title}", border_style="magenta"))


def style_for_risk(level: str) -> str:
    """Return Rich style for a risk level."""

    level = (level or "").upper()
    if level in {"CRITICAL", "HIGH"}:
        return "red bold"
    if level == "MEDIUM":
        return "yellow"
    return "green"


def print_report(report: dict[str, Any]) -> None:
    """Display a clean terminal summary report."""

    console.print(f"Target: {report.get('target', 'unknown')}", style="white bold")

    recon = report.get("recon", {})
    if recon:
        table = Table(title="Recon", show_lines=False)
        table.add_column("Item", style="cyan")
        table.add_column("Value")
        table.add_row("IP", str(recon.get("ip_address") or "not resolved"))
        ports = recon.get("open_ports", [])
        table.add_row(
            "Open Ports",
            ", ".join(
                f"[{item.get('source', 'ACTIVE')}] {item['port']} ({item['service']})"
                + (f" [{item.get('banner')}]" if item.get("banner") else "")
                for item in ports
            ) if ports else "none found",
        )
        subdomains = recon.get("subdomains", [])
        table.add_row(
            "Subdomains",
            ", ".join(f"[{item.get('source', 'PASSIVE')}] {item['host']}" for item in subdomains) if subdomains else "none found",
        )
        console.print(table)

    http_intel = report.get("http_intel")
    if http_intel:
        table = Table(title="HTTP Intelligence")
        table.add_column("URL", style="cyan")
        table.add_column("Server")
        table.add_column("X-Powered-By")
        table.add_column("Missing Headers", style="yellow")
        table.add_column("Cookie Issues", style="red")
        table.add_column("Frameworks", style="magenta")
        table.add_column("Source")
        for item in http_intel:
            table.add_row(
                str(item.get("final_url") or item.get("url")),
                str(item.get("server") or "unknown"),
                str(item.get("x_powered_by") or "unknown"),
                ", ".join(item.get("missing_security_headers", [])) or "none",
                ", ".join(item.get("cookies_missing_flags", [])) or "none",
                ", ".join(item.get("detected_frameworks", [])) or "none",
                f"[{item.get('source', 'ACTIVE')}]",
            )
        console.print(table)

    tls_certificate = report.get("tls_certificate")
    if tls_certificate:
        table = Table(title="TLS Certificate")
        table.add_column("Host", style="cyan")
        table.add_column("Issuer")
        table.add_column("Expiry")
        table.add_column("Days Left")
        table.add_column("Subject Alternative Names")
        table.add_column("Error", style="red")
        table.add_column("Source")
        item = tls_certificate
        table.add_row(
            str(item.get("host", "")),
            str(item.get("issuer_organization") or "unknown"),
            str(item.get("expiry_date") or "unknown"),
            str(item.get("days_until_expiry") if item.get("days_until_expiry") is not None else "unknown"),
            ", ".join(item.get("subject_alt_names", [])) or "none",
            str(item.get("error") or ""),
            f"[{item.get('source', 'ACTIVE')}]",
        )
        console.print(table)

    dns_intel = report.get("dns_intel")
    if dns_intel:
        table = Table(title="Email and DNS Intelligence")
        table.add_column("Domain", style="cyan")
        table.add_column("SPF")
        table.add_column("Mail Providers")
        table.add_column("DMARC")
        table.add_column("MX Records")
        table.add_column("Source")
        table.add_row(
            str(dns_intel.get("domain", "")),
            str(dns_intel.get("spf_record") or "not found"),
            ", ".join(dns_intel.get("mail_providers", [])) or "none",
            "present" if dns_intel.get("dmarc_present") else "missing",
            ", ".join(dns_intel.get("mx_records", [])) or "none",
            f"[{dns_intel.get('source', 'PASSIVE')}]",
        )
        console.print(table)

    known_cves = report.get("known_cves", [])
    if known_cves:
        table = Table(title="Known CVEs")
        table.add_column("CVE", style="cyan")
        table.add_column("Severity")
        table.add_column("Query")
        table.add_column("Description")
        for item in known_cves:
            table.add_row(
                item.get("id", ""),
                item.get("severity", "UNKNOWN"),
                item.get("query", ""),
                item.get("description", ""),
            )
        console.print(table)

    wayback = report.get("wayback")
    if wayback:
        table = Table(title="Wayback Intelligence")
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        table.add_row("Source", f"[{wayback.get('source', 'PASSIVE')}]")
        table.add_row("Archived URLs", str(len(wayback.get("urls", []))))
        table.add_row("Unique Parameters", str(len(wayback.get("params", []))))
        table.add_row("Old Endpoints", str(len(wayback.get("old_endpoints", []))))
        table.add_row("Fuzzer Targets", str(len(wayback.get("fuzzer_targets", []))))
        table.add_row("Saved URLs", str(wayback.get("saved_path", "")))
        console.print(table)

    js_analysis = report.get("js_analysis")
    if js_analysis:
        table = Table(title="JavaScript Analysis")
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        table.add_row("Source", f"[{js_analysis.get('source', 'ACTIVE')}]")
        table.add_row("Scripts", str(len(js_analysis.get("scripts", []))))
        table.add_row("Endpoints", str(len(js_analysis.get("endpoints", []))))
        table.add_row("Possible Secrets", str(len(js_analysis.get("secrets", []))))
        table.add_row("Discovery Paths", str(len(js_analysis.get("discovery_paths", []))))
        table.add_row("Errors", str(len(js_analysis.get("errors", []))))
        console.print(table)

        endpoints = js_analysis.get("endpoints", [])[:15]
        if endpoints:
            endpoint_table = Table(title="JavaScript Endpoints")
            endpoint_table.add_column("Endpoint", style="cyan")
            endpoint_table.add_column("Method")
            endpoint_table.add_column("Risk")
            endpoint_table.add_column("Source File")
            for item in endpoints:
                endpoint_table.add_row(
                    item.get("endpoint", ""),
                    item.get("method", ""),
                    item.get("risk", ""),
                    item.get("source_file", ""),
                )
            console.print(endpoint_table)

        secrets = js_analysis.get("secrets", [])[:15]
        if secrets:
            secret_table = Table(title="JavaScript Secret-Like Values")
            secret_table.add_column("Type", style="yellow")
            secret_table.add_column("Value")
            secret_table.add_column("File")
            secret_table.add_column("Line")
            for item in secrets:
                secret_table.add_row(
                    item.get("type", ""),
                    item.get("masked_value", "***"),
                    item.get("source_file", ""),
                    str(item.get("line", "")),
                )
            console.print(secret_table)

    origin_discovery = report.get("origin_discovery")
    if origin_discovery:
        table = Table(title="Origin IP Discovery")
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        table.add_row("Source", f"[{origin_discovery.get('source', 'PASSIVE')}]")
        table.add_row("Candidates", str(len(origin_discovery.get("candidates", []))))
        table.add_row("Fingerprint Comparisons", str(len(origin_discovery.get("comparisons", []))))
        table.add_row("Matches", str(len(origin_discovery.get("matches", []))))
        console.print(table)

        candidates = origin_discovery.get("candidates", [])[:20]
        if candidates:
            candidate_table = Table(title="Origin Candidates")
            candidate_table.add_column("IP", style="cyan")
            candidate_table.add_column("Source")
            for item in candidates:
                candidate_table.add_row(item.get("ip", ""), item.get("source", ""))
            console.print(candidate_table)

        matches = origin_discovery.get("matches", [])[:20]
        if matches:
            match_table = Table(title="Origin Fingerprint Matches")
            match_table.add_column("IP", style="cyan")
            match_table.add_column("Confidence")
            match_table.add_column("Reasons")
            for item in matches:
                match_table.add_row(
                    item.get("ip", ""),
                    item.get("confidence", ""),
                    ", ".join(item.get("reasons", [])),
                )
            console.print(match_table)

    verification = report.get("verification")
    if verification:
        table = Table(title="Vulnerability Verification")
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        table.add_row("Source", f"[{verification.get('source', 'ACTIVE')}]")
        table.add_row("Confirmed Signals", str(verification.get("confirmed_count", 0)))
        table.add_row("SQLi Checks", str(len(verification.get("sqli", []))))
        table.add_row("XSS Checks", str(len(verification.get("xss", []))))
        cors = verification.get("cors", {})
        table.add_row("CORS", f"{cors.get('confidence', 'LOW')} - {cors.get('evidence', '')}")
        console.print(table)

        rows = []
        for item in verification.get("sqli", []):
            rows.append(("SQLi", item))
        for item in verification.get("xss", []):
            rows.append(("XSS", item))
        if rows:
            detail_table = Table(title="Verification Details")
            detail_table.add_column("Type", style="cyan")
            detail_table.add_column("Parameter")
            detail_table.add_column("Confirmed")
            detail_table.add_column("Confidence")
            detail_table.add_column("Evidence")
            for vuln_type, item in rows[:20]:
                detail_table.add_row(
                    vuln_type,
                    item.get("param", ""),
                    str(item.get("confirmed", False)),
                    item.get("confidence", ""),
                    item.get("evidence", ""),
                )
            console.print(detail_table)

    auth_test = report.get("auth_test")
    if auth_test:
        table = Table(title="Authentication Testing")
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        table.add_row("Source", f"[{auth_test.get('source', 'ACTIVE')}]")
        table.add_row("Login Forms", str(len(auth_test.get("login_forms", []))))
        table.add_row("Rate Limit Tests", str(len(auth_test.get("rate_limit_tests", []))))
        table.add_row("JWT-like Tokens", str(len(auth_test.get("jwt_analysis", []))))
        table.add_row("Session Cookie Findings", str(len(auth_test.get("session_cookie_flags", []))))
        table.add_row("Errors", str(len(auth_test.get("errors", []))))
        console.print(table)

        forms = auth_test.get("login_forms", [])[:10]
        if forms:
            forms_table = Table(title="Login Forms")
            forms_table.add_column("Action", style="cyan")
            forms_table.add_column("Method")
            forms_table.add_column("Username Field")
            forms_table.add_column("Password Field")
            for item in forms:
                forms_table.add_row(
                    item.get("action", ""),
                    item.get("method", ""),
                    str(item.get("username_field") or ""),
                    str(item.get("password_field") or ""),
                )
            console.print(forms_table)

        cookies = auth_test.get("session_cookie_flags", [])[:10]
        if cookies:
            cookie_table = Table(title="Session Cookie Flags")
            cookie_table.add_column("Cookie", style="cyan")
            cookie_table.add_column("Secure")
            cookie_table.add_column("HttpOnly")
            cookie_table.add_column("SameSite")
            cookie_table.add_column("Issues", style="yellow")
            for item in cookies:
                cookie_table.add_row(
                    item.get("name", ""),
                    str(item.get("secure", False)),
                    str(item.get("httponly", False)),
                    str(item.get("samesite") or ""),
                    ", ".join(item.get("issues", [])),
                )
            console.print(cookie_table)

    fingerprint = report.get("fingerprint")
    if fingerprint:
        table = Table(title="Technology Fingerprinting")
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        table.add_row("Source", f"[{fingerprint.get('source', 'ACTIVE')}]")
        table.add_row("URL", str(fingerprint.get("url", "")))
        table.add_row("Technologies", str(len(fingerprint.get("technologies", []))))
        table.add_row("CVE Hints", str(len(fingerprint.get("cves", []))))
        if fingerprint.get("error"):
            table.add_row("Error", str(fingerprint.get("error")))
        console.print(table)

        technologies = fingerprint.get("technologies", [])[:20]
        if technologies:
            tech_table = Table(title="Detected Technologies")
            tech_table.add_column("Technology", style="cyan")
            tech_table.add_column("Version")
            tech_table.add_column("Confidence")
            tech_table.add_column("Evidence")
            for item in technologies:
                tech_table.add_row(
                    item.get("name", ""),
                    str(item.get("version") or ""),
                    item.get("confidence", ""),
                    ", ".join(item.get("evidence", [])),
                )
            console.print(tech_table)

    if "directory_discovery" in report:
        table = Table(title="Directory Discovery")
        table.add_column("Path", style="cyan")
        table.add_column("Status")
        table.add_column("Final URL")
        table.add_column("Risk")
        table.add_column("Note")
        table.add_column("Source")
        discovery = report.get("directory_discovery", [])
        if discovery:
            for item in discovery:
                table.add_row(
                    item["path"],
                    f"{item['status_code']} {item['reason']}",
                    item.get("final_url", item.get("url", "")),
                    f"[{style_for_risk(item.get('risk_level', 'LOW'))}]{item.get('risk_level', 'LOW')}[/]",
                    item.get("note", ""),
                    f"[{item.get('source', 'ACTIVE')}]",
                )
        else:
            table.add_row("none", "", "", "LOW", "No reportable paths found", "")
        console.print(table)

    fuzzing = report.get("fuzzing", {})
    if fuzzing:
        table = Table(title="Fuzzing Results")
        table.add_column("Parameter", style="cyan")
        table.add_column("Payload")
        table.add_column("Status")
        table.add_column("Length")
        table.add_column("Length Diff")
        table.add_column("Change Percent")
        table.add_column("Risk Level")
        table.add_column("Attack Type")
        table.add_column("Source")
        for item in fuzzing.get("results", []):
            risk = item.get("risk_level", "LOW")
            table.add_row(
                item.get("param", ""),
                item.get("payload", ""),
                str(item.get("status_code") if item.get("status_code") is not None else "ERR"),
                str(item.get("response_length", 0)),
                str(item.get("length_diff", 0)),
                f"{float(item.get('change_percent', 0.0)):.1f}%",
                f"[{style_for_risk(risk)}]{risk}[/]",
                item.get("attack_type", "unknown"),
                f"[{item.get('source', 'ACTIVE')}]",
            )
        console.print(table)

        summary = fuzzing.get("summary", {})
        if summary:
            for param, count in summary.items():
                console.print(f"Parameter '{param}' -> {count} vulnerabilities found", style="yellow")

        anomalies = fuzzing.get("anomalies", [])
        if anomalies:
            console.print(
                Panel(
                    "\n\n".join(format_flagged_result(item) for item in anomalies[:10]),
                    title="Smart Analysis - Flagged Anomalies",
                    border_style="yellow",
                )
            )

    risk = report.get("risk")
    if risk:
        console.print(
            Panel(
                "\n".join([f"Score: {risk['score']}", f"Level: {risk['level']}"] + risk.get("reasons", [])),
                title="Risk Score",
                border_style=style_for_risk(risk.get("level", "LOW")),
            )
        )

    suggestions = report.get("suggestions", [])
    if suggestions:
        console.print(Panel("\n".join(f"- {item}" for item in suggestions), title="Suggestions", border_style="cyan"))

    bounty_context = report.get("bounty_context", {})
    if bounty_context:
        findings = bounty_context.get("findings", [])
        table = Table(title="Bug Bounty Context")
        table.add_column("Title", style="cyan")
        table.add_column("Severity")
        table.add_column("Typical Bounty")
        table.add_column("Report Title")
        for item in findings[:15]:
            table.add_row(
                item.get("title", ""),
                item.get("severity", ""),
                item.get("typical_bounty", ""),
                item.get("report_title", ""),
            )
        if findings:
            console.print(table)
        if report.get("bounty_report"):
            console.print(f"[green][+] Bounty report skeleton: {report['bounty_report']}[/green]")

    learn_mode = report.get("learn_mode", {})
    if learn_mode:
        progress = learn_mode.get("progress", {})
        progress_lines = [
            f"Progress file: {learn_mode.get('progress_path', '')}",
            f"Mastered: {', '.join(progress.get('mastered', [])) or 'none'}",
            f"Not yet found: {', '.join(progress.get('not_yet_found', [])) or 'none'}",
        ]
        console.print(Panel("\n".join(progress_lines), title="Learn Mode Progress", border_style="blue"))

        findings = learn_mode.get("findings", [])
        if findings:
            table = Table(title="Learn Mode")
            table.add_column("Type", style="cyan")
            table.add_column("Analogy")
            table.add_column("Next Step")
            table.add_column("Report Score")
            for item in findings[:10]:
                quality = item.get("report_quality_check", {})
                next_steps = item.get("what_to_try_next", [])
                table.add_row(
                    item.get("type", ""),
                    item.get("analogy", ""),
                    next_steps[0] if next_steps else "",
                    str(quality.get("score", "")),
                )
            console.print(table)

    ai_analyses = report.get("ai_analyses", {})
    if ai_analyses:
        for key, content in ai_analyses.items():
            console.print(Panel(str(content), title=f"AI Analysis - {key.replace('_', ' ').title()}", border_style="magenta"))


def save_report(report: dict[str, Any], output_path: str | Path) -> Path:
    """Save a report as JSON or plain text based on file extension."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    serializable = _serializable(report)

    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(serializable, indent=2), encoding="utf-8")
    elif path.suffix.lower() == ".html":
        path.write_text(render_html_report(serializable), encoding="utf-8")
    else:
        path.write_text(render_text_report(serializable), encoding="utf-8")

    return path


def render_html_report(report: dict[str, Any]) -> str:
    """Render a dark themed HTML report with all scan sections."""

    template = Environment(autoescape=select_autoescape(["html"])).from_string(
        """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>MiniRecon Report - {{ report.target }}</title>
  <style>
    body { margin: 0; font-family: Segoe UI, Arial, sans-serif; background: #0f172a; color: #e5e7eb; }
    main { max-width: 1200px; margin: 0 auto; padding: 32px; }
    h1, h2 { color: #f8fafc; }
    section { margin: 24px 0; padding: 20px; background: #111827; border: 1px solid #243244; border-radius: 8px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { padding: 10px; border-bottom: 1px solid #243244; text-align: left; vertical-align: top; }
    th { color: #93c5fd; }
    .risk { display: inline-block; padding: 4px 8px; border-radius: 4px; background: #1f2937; }
    .HIGH, .CRITICAL { color: #fecaca; }
    .MEDIUM { color: #fde68a; }
    .LOW { color: #bbf7d0; }
    code { color: #a7f3d0; }
  </style>
</head>
<body>
<main>
  <h1>MiniRecon Report</h1>
  <p><strong>Target:</strong> {{ report.target }} | <strong>Mode:</strong> {{ report.mode }}</p>
  {% if report.auto_report or report.saved_report or report.bounty_report %}
  <section>
    <h2>Report Files</h2>
    {% if report.auto_report %}<p><strong>Auto report:</strong> {{ report.auto_report }}</p>{% endif %}
    {% if report.saved_report %}<p><strong>Saved report:</strong> {{ report.saved_report }}</p>{% endif %}
    {% if report.bounty_report %}<p><strong>Bounty report:</strong> {{ report.bounty_report }}</p>{% endif %}
  </section>
  {% endif %}

  {% if report.risk %}
  <section>
    <h2>Risk Score</h2>
    <p>Score: {{ report.risk.score }} | Level: <span class="risk {{ report.risk.level }}">{{ report.risk.level }}</span></p>
    <ul>{% for reason in report.risk.reasons %}<li>{{ reason }}</li>{% endfor %}</ul>
  </section>
  {% endif %}

  {% if report.recon %}
  <section>
    <h2>Open Ports</h2>
    <table><tr><th>Port</th><th>Service</th><th>Banner</th><th>Source</th></tr>
    {% for item in report.recon.open_ports %}<tr><td>{{ item.port }}</td><td>{{ item.service }}</td><td>{{ item.banner }}</td><td>[{{ item.source or 'ACTIVE' }}]</td></tr>{% endfor %}
    </table>
    <h2>Subdomains</h2>
    <table><tr><th>Host</th><th>Addresses</th><th>Live</th><th>HTTPS</th><th>Keywords</th><th>Source</th></tr>
    {% for item in report.recon.subdomains %}<tr><td>{{ item.host }}</td><td>{{ item.addresses|join(', ') }}</td><td>{{ item.live }}</td><td>{{ item.https }}</td><td>{{ item.keywords|join(', ') }}</td><td>[{{ item.source or 'PASSIVE' }}]</td></tr>{% endfor %}
    </table>
  </section>
  {% endif %}

  {% if report.http_intel %}
  <section>
    <h2>HTTP Intelligence</h2>
    <table><tr><th>URL</th><th>Server</th><th>X-Powered-By</th><th>Missing Headers</th><th>Cookie Issues</th><th>Frameworks</th><th>Source</th></tr>
    {% for item in report.http_intel %}<tr><td>{{ item.final_url or item.url }}</td><td>{{ item.server }}</td><td>{{ item.x_powered_by }}</td><td>{{ item.missing_security_headers|join(', ') }}</td><td>{{ item.cookies_missing_flags|join(', ') }}</td><td>{{ item.detected_frameworks|join(', ') }}</td><td>[{{ item.source or 'ACTIVE' }}]</td></tr>{% endfor %}
    </table>
  </section>
  {% endif %}

  {% if report.tls_certificate %}
  <section>
    <h2>TLS Certificate</h2>
    <p><strong>Host:</strong> {{ report.tls_certificate.host }}</p>
    <p><strong>Issuer:</strong> {{ report.tls_certificate.issuer_organization }}</p>
    <p><strong>Expiry:</strong> {{ report.tls_certificate.expiry_date }} | <strong>Days left:</strong> {{ report.tls_certificate.days_until_expiry }}</p>
    <p><strong>SANs:</strong> {{ report.tls_certificate.subject_alt_names|join(', ') }}</p>
    <p><strong>Source:</strong> [{{ report.tls_certificate.source or 'ACTIVE' }}]</p>
    {% if report.tls_certificate.error %}<p><strong>Error:</strong> {{ report.tls_certificate.error }}</p>{% endif %}
  </section>
  {% endif %}

  {% if report.dns_intel %}
  <section>
    <h2>Email and DNS Intelligence</h2>
    <p><strong>SPF:</strong> {{ report.dns_intel.spf_record or 'not found' }}</p>
    <p><strong>Mail providers:</strong> {{ report.dns_intel.mail_providers|join(', ') }}</p>
    <p><strong>DMARC:</strong> {{ 'present' if report.dns_intel.dmarc_present else 'missing' }}</p>
    <p><strong>MX:</strong> {{ report.dns_intel.mx_records|join(', ') }}</p>
    <p><strong>Source:</strong> [{{ report.dns_intel.source or 'PASSIVE' }}]</p>
  </section>
  {% endif %}

  {% if report.directory_discovery is defined %}
  <section>
    <h2>Directory Discovery</h2>
    <table><tr><th>Path</th><th>Status</th><th>Final URL</th><th>Risk</th><th>Note</th><th>Source</th></tr>
    {% for item in report.directory_discovery %}<tr><td>{{ item.path }}</td><td>{{ item.status_code }} {{ item.reason }}</td><td>{{ item.final_url }}</td><td>{{ item.risk_level }}</td><td>{{ item.note }}</td><td>[{{ item.source or 'ACTIVE' }}]</td></tr>{% endfor %}
    </table>
  </section>
  {% endif %}

  {% if report.fuzzing %}
  <section>
    <h2>Fuzzing Results</h2>
    <table><tr><th>Parameter</th><th>Payload</th><th>Status</th><th>Length</th><th>Length Diff</th><th>Change Percent</th><th>Similarity</th><th>Risk</th><th>Type</th><th>Source</th></tr>
    {% for item in report.fuzzing.results %}<tr><td>{{ item.param }}</td><td><code>{{ item.payload }}</code></td><td>{{ item.status_code }}</td><td>{{ item.response_length }}</td><td>{{ item.length_diff }}</td><td>{{ '%.1f'|format(item.change_percent) }}%</td><td>{{ '%.2f'|format(item.similarity_ratio) }}</td><td class="{{ item.risk_level }}">{{ item.risk_level }}</td><td>{{ item.attack_type }}</td><td>[{{ item.source or 'ACTIVE' }}]</td></tr>{% endfor %}
    </table>
  </section>
  {% endif %}

  {% if report.known_cves %}
  <section>
    <h2>Known CVEs</h2>
    <table><tr><th>CVE</th><th>Severity</th><th>Query</th><th>Description</th></tr>
    {% for item in report.known_cves %}<tr><td>{{ item.id }}</td><td>{{ item.severity }}</td><td>{{ item.query }}</td><td>{{ item.description }}</td></tr>{% endfor %}
    </table>
  </section>
  {% endif %}

  {% if report.wayback %}
  <section>
    <h2>Wayback Intelligence</h2>
    <p><strong>Source:</strong> [{{ report.wayback.source or 'PASSIVE' }}]</p>
    <p><strong>Archived URLs:</strong> {{ report.wayback.urls|length }}</p>
    <p><strong>Unique params:</strong> {{ report.wayback.params|length }}</p>
    <p><strong>Old endpoints:</strong> {{ report.wayback.old_endpoints|length }}</p>
    <p><strong>Fuzzer targets:</strong> {{ report.wayback.fuzzer_targets|length }}</p>
    <p><strong>Saved URLs:</strong> {{ report.wayback.saved_path }}</p>
    <h3>Parameters</h3>
    <p>{{ report.wayback.params|join(', ') }}</p>
    <h3>Old Endpoints</h3>
    <ul>{% for endpoint in report.wayback.old_endpoints[:50] %}<li><code>{{ endpoint }}</code></li>{% endfor %}</ul>
  </section>
  {% endif %}

  {% if report.js_analysis %}
  <section>
    <h2>JavaScript Analysis</h2>
    <p><strong>Source:</strong> [{{ report.js_analysis.source or 'ACTIVE' }}]</p>
    <p><strong>Scripts:</strong> {{ report.js_analysis.scripts|length }}</p>
    <p><strong>Endpoints:</strong> {{ report.js_analysis.endpoints|length }}</p>
    <p><strong>Possible secrets:</strong> {{ report.js_analysis.secrets|length }}</p>
    <p><strong>Discovery paths:</strong> {{ report.js_analysis.discovery_paths|length }}</p>
    <h3>Discovered Endpoints</h3>
    <table><tr><th>Endpoint</th><th>Method</th><th>Risk</th><th>Source File</th></tr>
    {% for item in report.js_analysis.endpoints[:50] %}<tr><td><code>{{ item.endpoint }}</code></td><td>{{ item.method }}</td><td>{{ item.risk }}</td><td>{{ item.source_file }}</td></tr>{% endfor %}
    </table>
    <h3>Secret-Like Values</h3>
    <table><tr><th>Type</th><th>Value</th><th>File</th><th>Line</th></tr>
    {% for item in report.js_analysis.secrets[:50] %}<tr><td>{{ item.type }}</td><td><code>{{ item.masked_value }}</code></td><td>{{ item.source_file }}</td><td>{{ item.line }}</td></tr>{% endfor %}
    </table>
  </section>
  {% endif %}

  {% if report.origin_discovery %}
  <section>
    <h2>Origin IP Discovery</h2>
    <p><strong>Source:</strong> [{{ report.origin_discovery.source or 'PASSIVE' }}]</p>
    <p><strong>Candidates:</strong> {{ report.origin_discovery.candidates|length }}</p>
    <p><strong>Fingerprint comparisons:</strong> {{ report.origin_discovery.comparisons|length }}</p>
    <p><strong>Matches:</strong> {{ report.origin_discovery.matches|length }}</p>
    <h3>Candidates</h3>
    <table><tr><th>IP</th><th>Source</th></tr>
    {% for item in report.origin_discovery.candidates[:50] %}<tr><td>{{ item.ip }}</td><td>{{ item.source }}</td></tr>{% endfor %}
    </table>
    <h3>Fingerprint Matches</h3>
    <table><tr><th>IP</th><th>Confidence</th><th>Reasons</th></tr>
    {% for item in report.origin_discovery.matches[:50] %}<tr><td>{{ item.ip }}</td><td>{{ item.confidence }}</td><td>{{ item.reasons|join(', ') }}</td></tr>{% endfor %}
    </table>
  </section>
  {% endif %}

  {% if report.verification %}
  <section>
    <h2>Vulnerability Verification</h2>
    <p><strong>Source:</strong> [{{ report.verification.source or 'ACTIVE' }}]</p>
    <p><strong>Confirmed signals:</strong> {{ report.verification.confirmed_count }}</p>
    <h3>SQLi</h3>
    <table><tr><th>Param</th><th>Confirmed</th><th>Confidence</th><th>Checks</th><th>Evidence</th></tr>
    {% for item in report.verification.sqli %}<tr><td>{{ item.param }}</td><td>{{ item.confirmed }}</td><td>{{ item.confidence }}</td><td>{{ item.checks|join(', ') }}</td><td>{{ item.evidence }}</td></tr>{% endfor %}
    </table>
    <h3>XSS</h3>
    <table><tr><th>Param</th><th>Confirmed</th><th>Confidence</th><th>Reflected</th><th>Stored</th><th>Evidence</th></tr>
    {% for item in report.verification.xss %}<tr><td>{{ item.param }}</td><td>{{ item.confirmed }}</td><td>{{ item.confidence }}</td><td>{{ item.reflected }}</td><td>{{ item.stored_reflected }}</td><td>{{ item.evidence }}</td></tr>{% endfor %}
    </table>
    <h3>CORS</h3>
    <p>{{ report.verification.cors.confidence }} - {{ report.verification.cors.evidence }}</p>
    <table><tr><th>Origin</th><th>Allowed Origin</th><th>Credentials</th><th>Risky</th></tr>
    {% for item in report.verification.cors.results %}<tr><td>{{ item.origin }}</td><td>{{ item.allowed_origin }}</td><td>{{ item.allow_credentials }}</td><td>{{ item.risky }}</td></tr>{% endfor %}
    </table>
  </section>
  {% endif %}

  {% if report.auth_test %}
  <section>
    <h2>Authentication Testing</h2>
    <p><strong>Source:</strong> [{{ report.auth_test.source or 'ACTIVE' }}]</p>
    <p><strong>Login forms:</strong> {{ report.auth_test.login_forms|length }}</p>
    <p><strong>Rate limit tests:</strong> {{ report.auth_test.rate_limit_tests|length }}</p>
    <p><strong>JWT-like tokens:</strong> {{ report.auth_test.jwt_analysis|length }}</p>
    <p><strong>Session cookie findings:</strong> {{ report.auth_test.session_cookie_flags|length }}</p>
    <h3>Login Forms</h3>
    <table><tr><th>Action</th><th>Method</th><th>Username Field</th><th>Password Field</th></tr>
    {% for item in report.auth_test.login_forms %}<tr><td>{{ item.action }}</td><td>{{ item.method }}</td><td>{{ item.username_field }}</td><td>{{ item.password_field }}</td></tr>{% endfor %}
    </table>
    <h3>JWT Analysis</h3>
    <table><tr><th>Location</th><th>Alg</th><th>Expires At</th><th>Expired</th><th>alg=none</th><th>Error</th></tr>
    {% for item in report.auth_test.jwt_analysis %}<tr><td>{{ item.location }}</td><td>{{ item.alg }}</td><td>{{ item.expires_at }}</td><td>{{ item.expired }}</td><td>{{ item.alg_none }}</td><td>{{ item.decode_error }}</td></tr>{% endfor %}
    </table>
    <h3>Session Cookies</h3>
    <table><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Issues</th></tr>
    {% for item in report.auth_test.session_cookie_flags %}<tr><td>{{ item.name }}</td><td>{{ item.secure }}</td><td>{{ item.httponly }}</td><td>{{ item.samesite }}</td><td>{{ item.issues|join(', ') }}</td></tr>{% endfor %}
    </table>
  </section>
  {% endif %}

  {% if report.fingerprint %}
  <section>
    <h2>Technology Fingerprinting</h2>
    <p><strong>Source:</strong> [{{ report.fingerprint.source or 'ACTIVE' }}]</p>
    <p><strong>URL:</strong> {{ report.fingerprint.url }}</p>
    <p><strong>Technologies:</strong> {{ report.fingerprint.technologies|length }}</p>
    <p><strong>CVE hints:</strong> {{ report.fingerprint.cves|length }}</p>
    {% if report.fingerprint.error %}<p><strong>Error:</strong> {{ report.fingerprint.error }}</p>{% endif %}
    <table><tr><th>Technology</th><th>Version</th><th>Confidence</th><th>Evidence</th></tr>
    {% for item in report.fingerprint.technologies %}<tr><td>{{ item.name }}</td><td>{{ item.version }}</td><td>{{ item.confidence }}</td><td>{{ item.evidence|join(', ') }}</td></tr>{% endfor %}
    </table>
  </section>
  {% endif %}

  {% if report.bounty_context %}
  <section>
    <h2>Bug Bounty Context And Remediation</h2>
    <p><strong>Frameworks:</strong> {{ report.bounty_context.frameworks|join(', ') }}</p>
    {% if report.bounty_report %}<p><strong>Markdown export:</strong> {{ report.bounty_report }}</p>{% endif %}
    {% for item in report.bounty_context.findings %}
    <article>
      <h3>{{ item.report_title }}</h3>
      <p><strong>Severity:</strong> {{ item.severity }} | <strong>Typical bounty:</strong> {{ item.typical_bounty }}</p>
      <p>{{ item.description }}</p>
      <p><strong>Higher value if:</strong> {{ item.higher_value_if }}</p>
      <p><strong>Lower value if:</strong> {{ item.lower_value_if }}</p>
      <p><strong>Remediation:</strong> {{ item.remediation }}</p>
      {% if item.framework_remediation %}
      <h4>Framework-Specific Remediation</h4>
      <ul>{% for fix in item.framework_remediation %}<li><code>{{ fix }}</code></li>{% endfor %}</ul>
      {% endif %}
      <h4>HackerOne Report Skeleton</h4>
      <pre>{{ item.report_skeleton }}</pre>
    </article>
    {% endfor %}
  </section>
  {% endif %}

  {% if report.learn_mode %}
  <section>
    <h2>Learn Mode</h2>
    <p><strong>Progress file:</strong> {{ report.learn_mode.progress_path }}</p>
    <p><strong>Mastered:</strong> {{ report.learn_mode.progress.mastered|join(', ') or 'none' }}</p>
    <p><strong>Not yet found:</strong> {{ report.learn_mode.progress.not_yet_found|join(', ') or 'none' }}</p>
    {% for item in report.learn_mode.findings %}
    <article>
      <h3>{{ item.type|upper }}</h3>
      <p><strong>Analogy:</strong> {{ item.analogy }}</p>
      <p><strong>Discovery story:</strong> {{ item.discovery_story }}</p>
      <h4>What To Try Next</h4>
      <ul>{% for step in item.what_to_try_next %}<li>{{ step }}</li>{% endfor %}</ul>
      <h4>Thought Experiment</h4>
      <p>{{ item.thought_experiment.question }}</p>
      <p><strong>A:</strong> {{ item.thought_experiment.option_a }}</p>
      <p><strong>B:</strong> {{ item.thought_experiment.option_b }}</p>
      <p>{{ item.thought_experiment.explanation }}</p>
      <h4>Report Quality Check</h4>
      <p><strong>Score:</strong> {{ item.report_quality_check.score }}/10</p>
      <ul>{% for issue in item.report_quality_check.issues %}<li>{{ issue }}</li>{% endfor %}</ul>
      <ul>{% for suggestion in item.report_quality_check.suggestions %}<li>{{ suggestion }}</li>{% endfor %}</ul>
    </article>
    {% endfor %}
  </section>
  {% endif %}

  {% if report.ai_analyses %}
  <section>
    <h2>AI Analysis</h2>
    {% for name, content in report.ai_analyses.items() %}
    <h3>{{ name|replace('_', ' ')|title }}</h3>
    <pre>{{ content }}</pre>
    {% endfor %}
  </section>
  {% endif %}
</main>
</body>
</html>
"""
    )
    return template.render(report=report)


def render_text_report(report: dict[str, Any]) -> str:
    """Render the report as plain text for .txt output."""

    lines: list[str] = [f"Target: {report.get('target', 'unknown')}"]

    if report.get("auto_report") or report.get("saved_report") or report.get("bounty_report"):
        lines.append("")
        lines.append("[Report Files]")
        if report.get("auto_report"):
            lines.append(f"- Auto Report: {report.get('auto_report')}")
        if report.get("saved_report"):
            lines.append(f"- Saved Report: {report.get('saved_report')}")
        if report.get("bounty_report"):
            lines.append(f"- Bounty Report: {report.get('bounty_report')}")

    risk = report.get("risk")
    if risk:
        lines.extend(["", "[Risk]", f"- Score: {risk['score']}", f"- Level: {risk['level']}"])

    recon = report.get("recon", {})
    if recon:
        lines.append("")
        lines.append("[Recon]")
        lines.append(f"- IP: {recon.get('ip_address') or 'not resolved'}")
        ports = recon.get("open_ports", [])
        lines.append(
            "- Open Ports: "
            + (
                ", ".join(
                    f"[{item.get('source', 'ACTIVE')}] {item['port']} ({item['service']})"
                    + (f" [{item.get('banner')}]" if item.get("banner") else "")
                    for item in ports
                )
                if ports
                else "none found"
            )
        )
        subdomains = recon.get("subdomains", [])
        lines.append("- Subdomains: " + (", ".join(f"[{item.get('source', 'PASSIVE')}] {item['host']}" for item in subdomains) if subdomains else "none found"))

    if report.get("tls_certificate"):
        tls = report["tls_certificate"]
        lines.append("")
        lines.append("[TLS Certificate]")
        lines.append(f"- Host: {tls.get('host')}")
        lines.append(f"- Issuer: {tls.get('issuer_organization') or 'unknown'}")
        lines.append(f"- Expiry: {tls.get('expiry_date') or 'unknown'}")
        lines.append(f"- Days Until Expiry: {tls.get('days_until_expiry')}")
        lines.append(f"- SANs: {', '.join(tls.get('subject_alt_names', [])) or 'none'}")

    if report.get("dns_intel"):
        dns = report["dns_intel"]
        lines.append("")
        lines.append("[Email and DNS Intelligence]")
        lines.append(f"- SPF: {dns.get('spf_record') or 'not found'}")
        lines.append(f"- Mail Providers: {', '.join(dns.get('mail_providers', [])) or 'none'}")
        lines.append(f"- DMARC: {'present' if dns.get('dmarc_present') else 'missing'}")
        lines.append(f"- MX: {', '.join(dns.get('mx_records', [])) or 'none'}")

    if report.get("known_cves"):
        lines.append("")
        lines.append("[Known CVEs]")
        for item in report["known_cves"]:
            lines.append(f"- {item.get('id')} | {item.get('severity')} | {item.get('query')} | {item.get('description')}")

    if report.get("wayback"):
        wayback = report["wayback"]
        lines.append("")
        lines.append("[Wayback Intelligence]")
        lines.append(f"- Source: [{wayback.get('source', 'PASSIVE')}]")
        lines.append(f"- Archived URLs: {len(wayback.get('urls', []))}")
        lines.append(f"- Unique Params: {len(wayback.get('params', []))}")
        lines.append(f"- Old Endpoints: {len(wayback.get('old_endpoints', []))}")
        lines.append(f"- Fuzzer Targets: {len(wayback.get('fuzzer_targets', []))}")
        lines.append(f"- Saved URLs: {wayback.get('saved_path', '')}")

    if report.get("js_analysis"):
        js_analysis = report["js_analysis"]
        lines.append("")
        lines.append("[JavaScript Analysis]")
        lines.append(f"- Source: [{js_analysis.get('source', 'ACTIVE')}]")
        lines.append(f"- Scripts: {len(js_analysis.get('scripts', []))}")
        lines.append(f"- Endpoints: {len(js_analysis.get('endpoints', []))}")
        lines.append(f"- Possible Secrets: {len(js_analysis.get('secrets', []))}")
        lines.append(f"- Discovery Paths: {len(js_analysis.get('discovery_paths', []))}")
        for item in js_analysis.get("endpoints", [])[:20]:
            lines.append(
                f"- Endpoint: {item.get('method', 'GET')} {item.get('endpoint', '')} "
                f"| Risk: {item.get('risk', 'LOW')} | File: {item.get('source_file', '')}"
            )
        for item in js_analysis.get("secrets", [])[:20]:
            lines.append(
                f"- Secret-like value: {item.get('type', '')} {item.get('masked_value', '***')} "
                f"| File: {item.get('source_file', '')}:{item.get('line', '')}"
            )

    if report.get("origin_discovery"):
        origin = report["origin_discovery"]
        lines.append("")
        lines.append("[Origin IP Discovery]")
        lines.append(f"- Source: [{origin.get('source', 'PASSIVE')}]")
        lines.append(f"- Candidates: {len(origin.get('candidates', []))}")
        lines.append(f"- Fingerprint Comparisons: {len(origin.get('comparisons', []))}")
        lines.append(f"- Matches: {len(origin.get('matches', []))}")
        for item in origin.get("candidates", [])[:20]:
            lines.append(f"- Candidate: {item.get('ip', '')} | Source: {item.get('source', '')}")
        for item in origin.get("matches", [])[:20]:
            lines.append(
                f"- Match: {item.get('ip', '')} | Confidence: {item.get('confidence', '')} "
                f"| Reasons: {', '.join(item.get('reasons', []))}"
            )

    if report.get("verification"):
        verification = report["verification"]
        lines.append("")
        lines.append("[Vulnerability Verification]")
        lines.append(f"- Source: [{verification.get('source', 'ACTIVE')}]")
        lines.append(f"- Confirmed Signals: {verification.get('confirmed_count', 0)}")
        for item in verification.get("sqli", [])[:20]:
            lines.append(
                f"- SQLi {item.get('param', '')}: confirmed={item.get('confirmed')} "
                f"confidence={item.get('confidence')} checks={', '.join(item.get('checks', []))} "
                f"evidence={item.get('evidence', '')}"
            )
        for item in verification.get("xss", [])[:20]:
            lines.append(
                f"- XSS {item.get('param', '')}: confirmed={item.get('confirmed')} "
                f"confidence={item.get('confidence')} reflected={item.get('reflected')} "
                f"stored={item.get('stored_reflected')} evidence={item.get('evidence', '')}"
            )
        cors = verification.get("cors", {})
        if cors:
            lines.append(f"- CORS: confirmed={cors.get('confirmed')} confidence={cors.get('confidence')} evidence={cors.get('evidence')}")

    if report.get("auth_test"):
        auth_test = report["auth_test"]
        lines.append("")
        lines.append("[Authentication Testing]")
        lines.append(f"- Source: [{auth_test.get('source', 'ACTIVE')}]")
        lines.append(f"- Login Forms: {len(auth_test.get('login_forms', []))}")
        lines.append(f"- Rate Limit Tests: {len(auth_test.get('rate_limit_tests', []))}")
        lines.append(f"- JWT-like Tokens: {len(auth_test.get('jwt_analysis', []))}")
        lines.append(f"- Session Cookie Findings: {len(auth_test.get('session_cookie_flags', []))}")
        for item in auth_test.get("login_forms", [])[:20]:
            lines.append(
                f"- Login form: {item.get('method', '')} {item.get('action', '')} "
                f"user={item.get('username_field')} password={item.get('password_field')}"
            )
        for item in auth_test.get("jwt_analysis", [])[:20]:
            lines.append(
                f"- JWT {item.get('location', '')}: alg={item.get('alg')} "
                f"expired={item.get('expired')} alg_none={item.get('alg_none')}"
            )
        for item in auth_test.get("session_cookie_flags", [])[:20]:
            lines.append(
                f"- Cookie {item.get('name', '')}: issues={', '.join(item.get('issues', []))}"
            )

    if report.get("fingerprint"):
        fingerprint = report["fingerprint"]
        lines.append("")
        lines.append("[Technology Fingerprinting]")
        lines.append(f"- Source: [{fingerprint.get('source', 'ACTIVE')}]")
        lines.append(f"- URL: {fingerprint.get('url', '')}")
        lines.append(f"- Technologies: {len(fingerprint.get('technologies', []))}")
        lines.append(f"- CVE Hints: {len(fingerprint.get('cves', []))}")
        if fingerprint.get("error"):
            lines.append(f"- Error: {fingerprint.get('error')}")
        for item in fingerprint.get("technologies", [])[:20]:
            lines.append(
                f"- Technology: {item.get('name', '')} {item.get('version') or ''} "
                f"| Confidence: {item.get('confidence', '')} | Evidence: {', '.join(item.get('evidence', []))}"
            )

    if report.get("bounty_context"):
        bounty = report["bounty_context"]
        lines.append("")
        lines.append("[Bug Bounty Context And Remediation]")
        lines.append(f"- Frameworks: {', '.join(bounty.get('frameworks', [])) or 'none'}")
        if report.get("bounty_report"):
            lines.append(f"- Markdown Export: {report.get('bounty_report')}")
        for item in bounty.get("findings", []):
            lines.append(f"- {item.get('report_title', '')}")
            lines.append(f"  Severity: {item.get('severity', '')}")
            lines.append(f"  Typical bounty: {item.get('typical_bounty', '')}")
            lines.append(f"  Higher value if: {item.get('higher_value_if', '')}")
            lines.append(f"  Lower value if: {item.get('lower_value_if', '')}")
            lines.append(f"  Remediation: {item.get('remediation', '')}")
            for fix in item.get("framework_remediation", []):
                lines.append(f"  Framework remediation: {fix}")

    if report.get("learn_mode"):
        learn = report["learn_mode"]
        progress = learn.get("progress", {})
        lines.append("")
        lines.append("[Learn Mode]")
        lines.append(f"- Progress File: {learn.get('progress_path', '')}")
        lines.append(f"- Mastered: {', '.join(progress.get('mastered', [])) or 'none'}")
        lines.append(f"- Not Yet Found: {', '.join(progress.get('not_yet_found', [])) or 'none'}")
        for item in learn.get("findings", []):
            lines.append(f"- {item.get('type', '').upper()}")
            lines.append(f"  Analogy: {item.get('analogy', '')}")
            lines.append(f"  Discovery story: {item.get('discovery_story', '')}")
            for step in item.get("what_to_try_next", []):
                lines.append(f"  What to try next: {step}")
            thought = item.get("thought_experiment", {})
            if thought:
                lines.append(f"  Thought experiment: {thought.get('question', '')}")
                lines.append(f"  Option A: {thought.get('option_a', '')}")
                lines.append(f"  Option B: {thought.get('option_b', '')}")
                lines.append(f"  Explanation: {thought.get('explanation', '')}")
            quality = item.get("report_quality_check", {})
            if quality:
                lines.append(f"  Report quality score: {quality.get('score', '')}/10")
                for issue in quality.get("issues", []):
                    lines.append(f"  Report issue: {issue}")
                for suggestion in quality.get("suggestions", []):
                    lines.append(f"  Report suggestion: {suggestion}")

    if report.get("ai_analyses"):
        lines.append("")
        lines.append("[AI Analysis]")
        for name, content in report["ai_analyses"].items():
            lines.append(f"- {name}: {content}")

    if "directory_discovery" in report:
        lines.append("")
        lines.append("[Directory Discovery]")
        for item in report.get("directory_discovery", []):
            lines.append(
                f"- {item['path']} -> {item['status_code']} {item['reason']} "
                f"{item.get('risk_level', 'LOW')} {item.get('note', '')}"
            )

    fuzzing = report.get("fuzzing", {})
    if fuzzing:
        lines.append("")
        lines.append("[Fuzzing]")
        for item in fuzzing.get("results", []):
            status = item["status_code"] if item["status_code"] is not None else "ERR"
            lines.append(
                f"- PARAM: {item.get('param')} | PAYLOAD: {item.get('payload')} | "
                f"STATUS: {status} | LENGTH: {item.get('response_length')} | "
                f"DIFF: {item.get('length_diff')} | CHANGE: {float(item.get('change_percent', 0.0)):.1f}% | "
                f"RISK: {item.get('risk_level')} | TYPE: {item.get('attack_type')}"
            )

    if report.get("suggestions"):
        lines.append("")
        lines.append("[Suggestions]")
        lines.extend(f"- {item}" for item in report["suggestions"])

    return "\n".join(lines) + "\n"
