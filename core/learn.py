"""Professional text-only learn mode."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


TRACKED_TYPES = ("sqli", "xss", "ssrf", "xxe", "ssti", "idor", "cors", "auth bypass")

ANALOGIES = {
    "sqli": "SQL injection is like adding extra instructions to a database request that the database cannot distinguish from the original question.",
    "xss": "Cross-site scripting is like placing untrusted text onto a sign where the browser treats part of the sign as instructions.",
    "ssrf": "Server-side request forgery is like convincing a server-side courier to visit an internal address on your behalf.",
    "xxe": "XML external entity injection is like letting a document reference files or network locations that the parser then reads.",
    "ssti": "Server-side template injection is like putting instructions into a template field that should have accepted only data.",
    "cors": "A CORS issue is like a receptionist sharing private documents with a caller from an untrusted office.",
    "auth": "Authentication weaknesses are like doors that record visitors but do not consistently verify or limit access attempts.",
    "auth bypass": "Authentication bypass is like a restricted door accepting a visitor who skipped the normal identity check.",
    "exposure": "Sensitive exposure is like leaving backup documents in a public hallway where anyone in scope can read them.",
    "generic": "A security finding is a signal that behavior differed from the expected safe path and needs controlled validation.",
}


def load_progress(path: str | Path) -> dict[str, list[str]]:
    """Load learn progress from disk."""

    progress_path = Path(path)
    if not progress_path.exists():
        return {"mastered": [], "not_yet_found": list(TRACKED_TYPES)}
    try:
        data = json.loads(progress_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"mastered": [], "not_yet_found": list(TRACKED_TYPES)}
    mastered = sorted({item.lower() for item in data.get("mastered", []) if item.lower() in TRACKED_TYPES})
    return {"mastered": mastered, "not_yet_found": [item for item in TRACKED_TYPES if item not in mastered]}


def save_progress(path: str | Path, progress: dict[str, list[str]]) -> Path:
    """Save learn progress to disk."""

    progress_path = Path(path)
    progress_path.parent.mkdir(parents=True, exist_ok=True)
    progress_path.write_text(json.dumps(progress, indent=2), encoding="utf-8")
    return progress_path


def update_progress(path: str | Path, finding_types: list[str]) -> dict[str, list[str]]:
    """Update mastered finding types."""

    progress = load_progress(path)
    mastered = set(progress["mastered"])
    for finding_type in finding_types:
        normalized = finding_type.lower()
        if normalized in TRACKED_TYPES:
            mastered.add(normalized)
        elif normalized == "auth":
            mastered.add("auth bypass")
    updated = {"mastered": sorted(mastered), "not_yet_found": [item for item in TRACKED_TYPES if item not in mastered]}
    save_progress(path, updated)
    return updated


def report_quality_score(skeleton: str) -> dict[str, Any]:
    """Score a report skeleton and identify concrete improvement areas."""

    score = 10
    issues: list[str] = []
    required_sections = ("Summary", "Affected Assets", "Steps To Reproduce", "Impact", "Remediation")
    for section in required_sections:
        if section.lower() not in skeleton.lower():
            score -= 2
            issues.append(f"Missing {section} section")
    if "Not captured" in skeleton:
        score -= 1
        issues.append("Affected asset is not specific enough")
    if len(skeleton.split()) < 80:
        score -= 1
        issues.append("Report is short; add stronger evidence and impact detail")
    return {
        "score": max(1, score),
        "issues": issues,
        "suggestions": [
            "Use a precise title with vulnerability type and affected component.",
            "Include the exact endpoint, parameter, and observed response difference.",
            "State the business or data-security impact in concrete terms.",
        ],
    }


def build_learn_block(finding: dict[str, Any]) -> dict[str, Any]:
    """Build a text-only learning block for one finding."""

    finding_type = str(finding.get("type", "generic")).lower()
    affected = ", ".join(finding.get("affected", [])) or "not captured"
    description = finding.get("description", "")
    skeleton = finding.get("report_skeleton", "")
    return {
        "type": finding_type,
        "analogy": ANALOGIES.get(finding_type, ANALOGIES["generic"]),
        "discovery_story": (
            f"MiniRecon observed this during the authorized scan: {description} "
            f"Affected asset: {affected}."
        ),
        "what_to_try_next": [
            "Reproduce the behavior manually in a controlled test account or lab target.",
            "Compare the response against a safe baseline request.",
            "Collect minimal evidence that proves impact without accessing unnecessary data.",
        ],
        "thought_experiment": {
            "question": "Which evidence is stronger for this finding?",
            "option_a": "A single unusual response with no impact statement.",
            "option_b": "A reproducible request pair showing baseline vs affected behavior plus clear impact.",
            "explanation": "Option B is stronger because it separates signal from noise and explains why the behavior matters.",
        },
        "report_quality_check": report_quality_score(skeleton),
    }


def build_learn_mode(bounty_context: dict[str, Any], progress_path: str | Path) -> dict[str, Any]:
    """Build learn-mode content and update progress."""

    findings = bounty_context.get("findings", [])
    types = [str(item.get("type", "generic")).lower() for item in findings]
    progress = update_progress(progress_path, types)
    return {
        "findings": [build_learn_block(item) for item in findings],
        "progress": progress,
        "progress_path": str(progress_path),
        "source": "LEARN",
    }
