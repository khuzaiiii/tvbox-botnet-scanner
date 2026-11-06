"""Device properties: model, build signing keys, debug flags."""

from __future__ import annotations

import re

from tvbox_scanner.models import Finding, Severity, TargetType

PROPS = [
    "ro.product.model",
    "ro.product.manufacturer",
    "ro.product.board",
    "ro.board.platform",
    "ro.build.fingerprint",
    "ro.build.version.release",
    "ro.build.tags",
    "ro.secure",
    "ro.debuggable",
]


def model_matches(known: str, model: str) -> bool:
    """Whole-word match, so "Q9" doesn't hit "TQ95" and "X88" doesn't hit "X880"."""
    words = r"[\s_-]*".join(re.escape(w) for w in re.split(r"[\s_-]+", known.strip()))
    return re.search(rf"(?<![a-z0-9]){words}(?![a-z0-9])", model, re.IGNORECASE) is not None


def read_props(adb) -> dict[str, str]:
    return {p: adb.shell(f"getprop {p}").strip() for p in PROPS}


def scan(adb, iocs, options) -> list[Finding]:
    props = read_props(adb)
    findings = []
    model = props["ro.product.model"].lower()

    for ioc in iocs:
        for known in ioc.device_models:
            if model_matches(known, model):
                findings.append(Finding(
                    scanner="device",
                    severity=Severity.MEDIUM,
                    title=f"Model '{props['ro.product.model']}' is on the {ioc.family} known-affected list",
                    target_type=TargetType.DEVICE,
                    target=props["ro.product.model"],
                    family=ioc.family,
                    detail="Model match alone is not proof of infection; check the other findings.",
                ))
                break  # one finding per family, even if "T95" and "T95MAX" both match

    if "test-keys" in props["ro.build.tags"]:
        findings.append(Finding(
            scanner="device",
            severity=Severity.LOW,
            title="Firmware signed with AOSP test-keys",
            target_type=TargetType.DEVICE,
            target="ro.build.tags",
            detail="Common on no-name boxes; means the firmware is not certified and system apps can be swapped freely.",
            evidence={"ro.build.tags": props["ro.build.tags"]},
        ))

    if props["ro.secure"] == "0" or props["ro.debuggable"] == "1":
        findings.append(Finding(
            scanner="device",
            severity=Severity.LOW,
            title="Insecure build (ro.secure=0 or ro.debuggable=1)",
            target_type=TargetType.DEVICE,
            target="ro.secure",
            detail="adbd can run as root; anything on the LAN with ADB access owns the box.",
            evidence={"ro.secure": props["ro.secure"], "ro.debuggable": props["ro.debuggable"]},
        ))

    return findings
