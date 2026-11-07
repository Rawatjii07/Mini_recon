"""TLS certificate intelligence using Python's standard ssl module."""

from __future__ import annotations

from datetime import datetime, timezone
import socket
import ssl
from typing import Any

from recon.portscan import normalize_host
from recon.subdomain import normalize_domain


def _issuer_organization(issuer: tuple[tuple[tuple[str, str], ...], ...]) -> str | None:
    for group in issuer:
        for key, value in group:
            if key == "organizationName":
                return value
    return None


def _subject_alt_names(cert: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for name_type, value in cert.get("subjectAltName", []):
        if name_type.lower() == "dns":
            names.append(value.lower())
    return sorted(set(names))


def analyze_tls_certificate(target: str, timeout: float = 5.0, ca_cert: str | None = None) -> dict[str, Any]:
    """Connect to port 443 and extract certificate expiry, issuer, and SANs."""

    host = normalize_host(target)
    result: dict[str, Any] = {
        "host": host,
        "expiry_date": None,
        "issuer_organization": None,
        "subject_alt_names": [],
        "days_until_expiry": None,
        "error": None,
    }

    cert = None
    try:
        context = ssl.create_default_context()
        if ca_cert:
            context.load_verify_locations(cafile=ca_cert)
        with socket.create_connection((host, 443), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
    except ssl.SSLCertVerificationError:
        # Fall back to unverified peer cert inspection for self-signed lab targets
        try:
            unverified_ctx = ssl._create_unverified_context()
            with socket.create_connection((host, 443), timeout=timeout) as raw_sock:
                with unverified_ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
            result["note"] = "Self-signed or unverified certificate"
        except (OSError, ssl.SSLError) as exc:
            result["error"] = str(exc)
            return result
    except (OSError, ssl.SSLError) as exc:
        result["error"] = str(exc)
        return result

    if not cert:
        return result

    not_after = cert.get("notAfter")
    result["issuer_organization"] = _issuer_organization(cert.get("issuer", ()))
    result["subject_alt_names"] = _subject_alt_names(cert)

    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            result["expiry_date"] = expiry.isoformat()
            result["days_until_expiry"] = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            result["expiry_date"] = not_after

    return result


def san_subdomains_for_target(target: str, subject_alt_names: list[str]) -> list[str]:
    """Return SAN names that are concrete subdomains of the target domain."""

    domain = normalize_domain(target)
    suffix = f".{domain}"
    subdomains: list[str] = []
    for name in subject_alt_names:
        normalized = name.lower().lstrip("*.")
        if normalized.endswith(suffix) and normalized != domain:
            subdomains.append(normalized)
    return sorted(set(subdomains))
