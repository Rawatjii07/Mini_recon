"""NVIDIA NIM AI analyst integration.

API keys must be loaded from .env only. Never hardcode secrets in this project.
"""

from __future__ import annotations

import json
import os
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()

MODEL = "meta/llama-3.1-70b-instruct"
BASE_URL = "https://integrate.api.nvidia.com/v1"


def ai_configured() -> bool:
    """Return True when NVIDIA_API_KEY is available from the environment."""

    return bool(os.environ.get("NVIDIA_API_KEY"))


def get_client() -> OpenAI:
    """Create an OpenAI-compatible NVIDIA NIM client."""

    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        raise RuntimeError("NVIDIA_API_KEY not found. Create .env from .env.example first.")
    return OpenAI(base_url=BASE_URL, api_key=api_key)


def call_ai(system_prompt: str, user_prompt: str) -> str:
    """Call the configured NVIDIA NIM model with safe error handling."""

    try:
        client = get_client()
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
            max_tokens=900,
        )
        return response.choices[0].message.content or "No response returned from model."
    except Exception as exc:
        return f"[AI Analysis Unavailable: {exc}]"


def detect_anomalies(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Statistical anomaly detection based on response length."""

    if not responses:
        return []
    avg = sum(int(item.get("length", item.get("response_length", 0))) for item in responses) / len(responses)
    return [
        item
        for item in responses
        if abs(int(item.get("length", item.get("response_length", 0))) - avg) > 800
    ]


def ai_analyze_ports(port_data: list[dict[str, Any]]) -> str:
    """AI explanation of open ports and likely security impact."""

    if not ai_configured():
        return "AI disabled: NVIDIA_API_KEY not found in .env."
    prompt = (
        "Analyze these open TCP ports for an authorized security assessment. "
        "Explain what each port usually means, what service may be running, "
        "what an attacker would typically try next, and assign a concise risk level.\n\n"
        f"{json.dumps(port_data, indent=2)}"
    )
    return call_ai(
        "You are a professional penetration testing analyst. Keep guidance defensive and authorized.",
        prompt,
    )


def ai_analyze_dirs(dir_data: list[dict[str, Any]]) -> str:
    """AI explanation of discovered directories and risky files."""

    if not ai_configured():
        return "AI disabled: NVIDIA_API_KEY not found in .env."
    prompt = (
        "Analyze these discovered web paths. Identify dangerous directories or files, "
        "why each is risky, and what the defender/tester should verify next.\n\n"
        f"{json.dumps(dir_data, indent=2)}"
    )
    return call_ai(
        "You are a professional web security analyst. Keep advice authorized and defensive.",
        prompt,
    )


def ai_analyze_fuzz(fuzz_data: list[dict[str, Any]]) -> str:
    """AI interpretation of anomalous fuzzing results grouped by parameter."""

    if not ai_configured():
        return "AI disabled: NVIDIA_API_KEY not found in .env."
    anomalies = detect_anomalies(fuzz_data)
    prompt = (
        "Interpret these parameter fuzzing results. Group findings by parameter, "
        "identify SQLi/XSS/LFI/SSTI patterns, explain what each anomalous response "
        "means in plain English, and recommend validation steps.\n\n"
        f"Anomalies by length:\n{json.dumps(anomalies, indent=2)}\n\n"
        f"All fuzz results:\n{json.dumps(fuzz_data, indent=2)}"
    )
    return call_ai(
        "You are a professional penetration testing analyst. Avoid exploit instructions against unauthorized systems.",
        prompt,
    )


def ai_analyze_headers(header_data: dict[str, Any] | list[dict[str, Any]]) -> str:
    """AI explanation of missing HTTP security headers."""

    if not ai_configured():
        return "AI disabled: NVIDIA_API_KEY not found in .env."
    prompt = (
        "Analyze this HTTP intelligence data. Explain missing security headers, weak cookies, "
        "framework hints, redirect behavior, and a concise fix priority order.\n\n"
        f"{json.dumps(header_data, indent=2)}"
    )
    return call_ai(
        "You are a web application security analyst focused on defensive remediation.",
        prompt,
    )


def ai_analyze_summary(all_data: dict[str, Any]) -> str:
    """AI-generated professional summary across all scan modules."""

    if not ai_configured():
        return "AI disabled: NVIDIA_API_KEY not found in .env."
    prompt = (
        "Write a concise professional penetration testing summary from this authorized scan data. "
        "Assign overall risk CRITICAL/HIGH/MEDIUM/LOW and list the top 5 recommended actions "
        "in priority order.\n\n"
        f"{json.dumps(all_data, indent=2)}"
    )
    return call_ai(
        "You are a senior penetration testing report writer. Keep the report practical and defensive.",
        prompt,
    )


def analyze_ports(open_ports: list[dict[str, Any]]) -> str:
    """Backward-compatible wrapper."""

    return ai_analyze_ports(open_ports)


def analyze_directories(found_dirs: list[dict[str, Any]]) -> str:
    """Backward-compatible wrapper."""

    return ai_analyze_dirs(found_dirs)


def analyze_fuzzing(fuzz_results: list[dict[str, Any]]) -> str:
    """Backward-compatible wrapper."""

    return ai_analyze_fuzz(fuzz_results)


def analyze_headers(missing_headers: list[str]) -> str:
    """Backward-compatible wrapper."""

    return ai_analyze_headers({"missing_security_headers": missing_headers})


def generate_final_report(scan_data: dict[str, Any]) -> str:
    """Backward-compatible wrapper."""

    return ai_analyze_summary(scan_data)
