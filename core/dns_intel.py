"""Email and DNS intelligence helpers."""

from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver

from recon.subdomain import normalize_domain


def _txt_values(name: str, timeout: float) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answers = resolver.resolve(name, "TXT")
    except dns.exception.DNSException:
        return []
    values: list[str] = []
    for answer in answers:
        values.append("".join(part.decode("utf-8", errors="ignore") for part in answer.strings))
    return values


def _mx_values(domain: str, timeout: float) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answers = resolver.resolve(domain, "MX")
    except dns.exception.DNSException:
        return []
    return sorted({str(answer.exchange).rstrip(".") for answer in answers})


def extract_mail_providers(spf_record: str | None) -> list[str]:
    """Extract visible provider hints from an SPF record."""

    if not spf_record:
        return []
    providers: list[str] = []
    for token in spf_record.split():
        if token.startswith("include:"):
            providers.append(token.split(":", 1)[1])
        elif token in {"mx", "a"} or token.startswith(("ip4:", "ip6:")):
            providers.append(token)
    return sorted(set(providers))


def collect_dns_email_intel(target: str, timeout: float = 3.0) -> dict[str, Any]:
    """Collect SPF, DMARC, and MX information for the target domain."""

    domain = normalize_domain(target)
    txt_records = _txt_values(domain, timeout)
    dmarc_records = _txt_values(f"_dmarc.{domain}", timeout)
    spf_record = next((item for item in txt_records if item.lower().startswith("v=spf1")), None)
    dmarc_record = next((item for item in dmarc_records if item.lower().startswith("v=dmarc1")), None)

    return {
        "domain": domain,
        "spf_record": spf_record,
        "mail_providers": extract_mail_providers(spf_record),
        "dmarc_record": dmarc_record,
        "dmarc_present": dmarc_record is not None,
        "mx_records": _mx_values(domain, timeout),
    }
