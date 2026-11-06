"""Export domain/IP IOCs for a DNS sinkhole or firewall.

This is the only defence that works when firmware malware can't be removed.
"""

from __future__ import annotations


def export_blocklist(iocs, fmt: str = "hosts") -> str:
    domains = sorted({d for ioc in iocs for d in ioc.domains})
    ips = sorted({ip for ioc in iocs for ip in ioc.ips})
    if fmt == "hosts":
        return "\n".join(f"0.0.0.0 {d}" for d in domains) + "\n"
    if fmt == "domains":  # Pi-hole / AdGuard Home plain list
        return "\n".join(domains) + "\n"
    if fmt == "ips":
        return "\n".join(ips) + "\n"
    raise ValueError(f"unknown format: {fmt}")
