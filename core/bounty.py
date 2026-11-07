"""Bug bounty context, report skeletons, and remediation guidance."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


BOUNTY_RANGES = {
    "sqli": ("$500-$5,000", "data extraction, auth bypass, or write access", "only generic errors or no sensitive data"),
    "xss": ("$100-$2,500", "account takeover, privileged context, or stored behavior", "self-XSS or heavily constrained context"),
    "lfi": ("$250-$3,000", "source/config disclosure or credential access", "only harmless local files"),
    "ssti": ("$500-$5,000", "server-side execution or sensitive config access", "only arithmetic evaluation"),
    "ssrf": ("$300-$4,000", "cloud metadata or internal admin access", "blocked egress or no sensitive internal reachability"),
    "cors": ("$100-$1,500", "credentialed cross-origin read of sensitive data", "no credentials or no sensitive endpoint"),
    "auth": ("$100-$2,000", "lockout bypass, weak sessions, or JWT trust issues", "only informational cookie flags"),
    "exposure": ("$100-$2,500", "secrets, backups, or source code disclosure", "public non-sensitive content"),
    "generic": ("$50-$500", "clear security impact and reproducible evidence", "missing impact or low sensitivity"),
}

REMEDIATION = {
    "generic": "Validate all findings manually, minimize exposed surface area, and apply least-privilege controls.",
    "sqli": "Use parameterized queries, avoid string-concatenated SQL, and add regression tests for tainted inputs.",
    "xss": "Contextually encode output, avoid unsafe HTML sinks, and enforce a restrictive Content Security Policy.",
    "lfi": "Normalize paths, enforce an allow-list of readable files, and keep user input away from filesystem paths.",
    "ssti": "Do not render user-controlled template strings; pass user input as data only.",
    "ssrf": "Use outbound allow-lists, block link-local/internal ranges, and avoid fetching arbitrary user-provided URLs.",
    "cors": "Return explicit trusted origins only and avoid credentialed wildcard/reflective CORS policies.",
    "auth": "Use strong session cookie flags, safe JWT algorithms, expiry checks, and rate limiting on login endpoints.",
    "exposure": "Remove exposed sensitive files, rotate leaked credentials, and prevent deployment of backups or dotfiles.",
}

FRAMEWORK_FIXES = {
    "Flask": "Use parameter binding: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    "Laravel": "Use Eloquent/query bindings: User::where('id', $id)->first(); never concatenate raw SQL.",
    "React": "Render text as normal JSX. Avoid dangerouslySetInnerHTML; sanitize trusted HTML with a vetted sanitizer.",
    "WordPress": "Use $wpdb->prepare('SELECT * FROM table WHERE id = %d', $id) before database queries.",
}


@dataclass(frozen=True)
class BountyFinding:
    """Enriched bounty context for one finding."""

    title: str
    type: str
    severity: str
    affected: tuple[str, ...]
    description: str
    typical_bounty: str
    higher_value_if: str
    lower_value_if: str
    report_title: str
    report_skeleton: str
    remediation: str
    framework_remediation: tuple[str, ...]
    source: str = "ANALYSIS"


def _severity_from_risk(risk: str | None) -> str:
    risk = (risk or "LOW").upper()
    if risk in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return risk
    return "LOW"


def _framework_names(scan_data: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for item in scan_data.get("fingerprint", []):
        for tech in item.get("technologies", []):
            name = tech.get("name")
            if name and name not in names:
                names.append(name)
    return names


def _context_for(vuln_type: str) -> tuple[str, str, str]:
    return BOUNTY_RANGES.get(vuln_type, BOUNTY_RANGES["generic"])


def _framework_remediation(vuln_type: str, frameworks: list[str]) -> tuple[str, ...]:
    snippets: list[str] = []
    for framework in frameworks:
        if framework in FRAMEWORK_FIXES and (vuln_type in {"sqli", "xss"} or framework in {"Flask", "Laravel", "React", "WordPress"}):
            snippets.append(f"{framework}: {FRAMEWORK_FIXES[framework]}")
    return tuple(snippets)


def _skeleton(title: str, severity: str, affected: list[str], description: str, impact: str, remediation: str) -> str:
    affected_text = "\n".join(f"- {item}" for item in affected) if affected else "- Not captured"
    return (
        f"# {title}\n\n"
        f"Severity: {severity}\n\n"
        "## Summary\n"
        f"{description}\n\n"
        "## Affected Assets\n"
        f"{affected_text}\n\n"
        "## Steps To Reproduce\n"
        "1. Run the MiniRecon command used for this authorized assessment.\n"
        "2. Review the evidence in the generated scan report.\n"
        "3. Manually confirm the behavior in a controlled test account or environment.\n\n"
        "## Impact\n"
        f"{impact}\n\n"
        "## Remediation\n"
        f"{remediation}\n"
    )


def finding_from_fuzz(item: dict[str, Any], frameworks: list[str]) -> BountyFinding:
    vuln_type = item.get("attack_type") or "generic"
    bounty, higher, lower = _context_for(vuln_type)
    param = item.get("param", "")
    url = item.get("url", "")
    severity = _severity_from_risk(item.get("risk_level"))
    title = f"Potential {vuln_type.upper()} behavior on parameter {param}".strip()
    description = f"Payload `{item.get('payload', '')}` produced an unusual response: {item.get('reason', 'review required')}."
    remediation = REMEDIATION.get(vuln_type, REMEDIATION["generic"])
    affected = [url] if url else []
    return BountyFinding(
        title=title,
        type=vuln_type,
        severity=severity,
        affected=tuple(affected),
        description=description,
        typical_bounty=bounty,
        higher_value_if=higher,
        lower_value_if=lower,
        report_title=f"{severity}: Potential {vuln_type.upper()} in `{param}` parameter",
        report_skeleton=_skeleton(title, severity, affected, description, higher, remediation),
        remediation=remediation,
        framework_remediation=_framework_remediation(vuln_type, frameworks),
    )


def finding_from_directory(item: dict[str, Any], frameworks: list[str]) -> BountyFinding:
    path = item.get("path", "")
    note = item.get("note", "")
    vuln_type = "exposure"
    bounty, higher, lower = _context_for(vuln_type)
    severity = _severity_from_risk(item.get("risk_level"))
    title = f"Potential sensitive exposure at {path}"
    description = f"Directory discovery reported `{path}` with status {item.get('status_code')} {item.get('reason', '')}. {note}".strip()
    remediation = REMEDIATION[vuln_type]
    affected = [item.get("url", path)]
    return BountyFinding(
        title=title,
        type=vuln_type,
        severity=severity,
        affected=tuple(affected),
        description=description,
        typical_bounty=bounty,
        higher_value_if=higher,
        lower_value_if=lower,
        report_title=f"{severity}: Potential sensitive file or admin path exposure at `{path}`",
        report_skeleton=_skeleton(title, severity, affected, description, higher, remediation),
        remediation=remediation,
        framework_remediation=_framework_remediation(vuln_type, frameworks),
    )


def finding_from_verification(item: dict[str, Any], vuln_type: str, frameworks: list[str]) -> BountyFinding:
    bounty, higher, lower = _context_for(vuln_type)
    severity = "HIGH" if item.get("confirmed") else "MEDIUM"
    param = item.get("param", "")
    title = f"Verified {vuln_type.upper()} signal on parameter {param}".strip()
    description = item.get("evidence", "Verification signal observed.")
    remediation = REMEDIATION.get(vuln_type, REMEDIATION["generic"])
    affected = [item.get("url", "")]
    return BountyFinding(
        title=title,
        type=vuln_type,
        severity=severity,
        affected=tuple(item for item in affected if item),
        description=description,
        typical_bounty=bounty,
        higher_value_if=higher,
        lower_value_if=lower,
        report_title=f"{severity}: Verified {vuln_type.upper()} behavior in `{param}`",
        report_skeleton=_skeleton(title, severity, affected, description, higher, remediation),
        remediation=remediation,
        framework_remediation=_framework_remediation(vuln_type, frameworks),
    )


def build_bounty_context(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Build bounty context and remediation for discovered findings."""

    frameworks = _framework_names(scan_data)
    findings: list[BountyFinding] = []
    for item in scan_data.get("fuzzing", []):
        if item.get("possible_vulnerability"):
            findings.append(finding_from_fuzz(item, frameworks))
    for item in scan_data.get("directories", []):
        if item.get("risk_level") == "HIGH":
            findings.append(finding_from_directory(item, frameworks))
    for verification in scan_data.get("verification", []):
        for item in verification.get("sqli", []):
            if item.get("confirmed"):
                findings.append(finding_from_verification(item, "sqli", frameworks))
        for item in verification.get("xss", []):
            if item.get("confirmed"):
                findings.append(finding_from_verification(item, "xss", frameworks))
        cors = verification.get("cors", {})
        if cors.get("confirmed"):
            findings.append(finding_from_verification({"param": "Origin", "url": cors.get("url", ""), "confirmed": True, "evidence": cors.get("evidence", "")}, "cors", frameworks))

    return {
        "findings": [asdict(item) for item in findings],
        "frameworks": frameworks,
        "source": "ANALYSIS",
    }


def export_bounty_markdown(context: dict[str, Any], output_path: str | Path) -> Path:
    """Export all report skeletons into one Markdown file."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    sections = []
    for index, finding in enumerate(context.get("findings", []), start=1):
        sections.append(f"<!-- Finding {index}: {finding.get('title', '')} -->\n\n{finding.get('report_skeleton', '')}")
    path.write_text("\n\n---\n\n".join(sections) if sections else "# No bounty findings generated\n", encoding="utf-8")
    return path
