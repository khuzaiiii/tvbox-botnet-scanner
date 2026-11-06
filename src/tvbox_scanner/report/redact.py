"""Strip details that identify a home network before a report is shared publicly.

Masks LAN addresses and the value of the system proxy setting (often an internal host).
Public C2 addresses and domains stay: they're IOCs, and the point of sharing.
"""

from __future__ import annotations

import copy
import ipaddress
import re

from tvbox_scanner.models import ScanResult

PRIVATE_SETTINGS = {"http_proxy", "global_http_proxy_host"}
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
MASK = "<redacted>"


def _mask_ip(match: re.Match) -> str:
    try:
        ip = ipaddress.IPv4Address(match.group(1))
    except ValueError:
        return match.group(0)
    return "<lan-ip>" if (ip.is_private or ip.is_link_local) and not ip.is_loopback else match.group(0)


def redact_text(value: str) -> str:
    return _IPV4.sub(_mask_ip, value)


def _walk(value, key: str = ""):
    if key in PRIVATE_SETTINGS:
        return MASK
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: _walk(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(v) for v in value]
    return value


def redacted(result: ScanResult) -> ScanResult:
    out = copy.deepcopy(result)
    out.device = _walk(out.device)
    out.errors = _walk(out.errors)
    for f in out.findings:
        for secret in (str(v) for k, v in f.evidence.items() if k in PRIVATE_SETTINGS):
            f.title = f.title.replace(secret, MASK)
        f.title = redact_text(f.title)
        f.detail = redact_text(f.detail)
        f.target = redact_text(f.target)
        f.evidence = _walk(f.evidence)
    return out
