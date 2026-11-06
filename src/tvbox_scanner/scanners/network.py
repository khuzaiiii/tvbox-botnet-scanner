"""Live TCP connections to known C2 IPs, read from /proc/net/tcp{,6}.

Domain IOCs can't be checked here (no DNS log on the box); export them with
`tvbox-scan export-blocklist` and block them at the router / Pi-hole instead.
"""

from __future__ import annotations

import ipaddress
import socket
import struct

from tvbox_scanner.models import Finding, Severity, TargetType

TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT"}


def _decode_v4(hex_addr: str) -> str:
    return socket.inet_ntoa(struct.pack("<I", int(hex_addr, 16)))


def _decode_v6(hex_addr: str) -> str:
    raw = b"".join(struct.pack("<I", int(hex_addr[i:i + 8], 16)) for i in range(0, 32, 8))
    addr = ipaddress.IPv6Address(raw)
    return str(addr.ipv4_mapped or addr)


def remote_endpoints(adb) -> list[tuple[str, int, str]]:
    result = []
    for path, decode in (("/proc/net/tcp", _decode_v4), ("/proc/net/tcp6", _decode_v6)):
        for line in adb.shell(f"cat {path} 2>/dev/null").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[3] not in TCP_STATES:
                continue
            ip_hex, port_hex = parts[2].split(":")
            result.append((decode(ip_hex), int(port_hex, 16), TCP_STATES[parts[3]]))
    return result


def scan(adb, iocs, options) -> list[Finding]:
    ip_family = {ip: ioc.family for ioc in iocs for ip in ioc.ips}
    if not ip_family:
        return []
    findings = []
    for ip, port, state in remote_endpoints(adb):
        if ip in ip_family:
            findings.append(Finding(
                scanner="network",
                severity=Severity.HIGH,
                title=f"Connection to {ip_family[ip]} C2 {ip}:{port} ({state})",
                target_type=TargetType.NETWORK,
                target=f"{ip}:{port}",
                family=ip_family[ip],
                evidence={"ip": ip, "port": port, "state": state},
            ))
    return findings
