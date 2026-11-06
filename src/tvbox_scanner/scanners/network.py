"""Live TCP connections to known C2 IPs (read from /proc/net/tcp{,6}), and DNS settings
that point at a known C2 domain or IP.

The box keeps no DNS log, so lookups of C2 domains can't be seen here; export them with
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


def _rows(adb):
    """Yield (decode, local, remote, state) for every parsable row of /proc/net/tcp{,6}."""
    for path, decode in (("/proc/net/tcp", _decode_v4), ("/proc/net/tcp6", _decode_v6)):
        for line in adb.shell(f"cat {path} 2>/dev/null").splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[1].count(":") == 1 and parts[2].count(":") == 1:
                yield decode, parts[1], parts[2], parts[3]


def remote_endpoints(adb) -> list[tuple[str, int, str]]:
    result = []
    for decode, _, remote, state in _rows(adb):
        if state in TCP_STATES:
            ip_hex, port_hex = remote.split(":")
            result.append((decode(ip_hex), int(port_hex, 16), TCP_STATES[state]))
    return result


def listening_ports(adb) -> set[int]:
    """TCP ports listening on every interface (0.0.0.0 or ::), not just loopback."""
    ports = set()
    for decode, local, _, state in _rows(adb):
        ip_hex, port_hex = local.split(":")
        if state == "0A" and decode(ip_hex) in ("0.0.0.0", "::"):  # noqa: S104 (reading, not binding)
            ports.add(int(port_hex, 16))
    return ports


DNS_SETTINGS = {
    "private_dns_specifier": "settings get global private_dns_specifier",
    "net.dns1": "getprop net.dns1",
    "net.dns2": "getprop net.dns2",
}


def _dns(adb, iocs) -> list[Finding]:
    findings = []
    for name, command in DNS_SETTINGS.items():
        value = adb.shell(command).strip().lower().rstrip(".")
        if not value or value == "null":
            continue
        for ioc in iocs:
            hit = value in ioc.ips or any(value == d or value.endswith("." + d) for d in ioc.domains)
            if hit:
                findings.append(Finding(
                    scanner="network",
                    severity=Severity.HIGH,
                    title=f"DNS setting points at {ioc.family} infrastructure: {name}={value}",
                    target_type=TargetType.DEVICE,
                    target=name,
                    family=ioc.family,
                    detail="Every lookup the box makes goes to a server the botnet controls. Reset DNS in "
                           "Settings > Network, and block the botnet's domains on the router.",
                    evidence={"setting": name, "value": value},
                ))
                break
    return findings


def scan(adb, iocs, options) -> list[Finding]:
    ip_family = {ip: ioc.family for ioc in iocs for ip in ioc.ips}
    findings = _dns(adb, iocs)
    if not ip_family:
        return findings
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
