"""Each scanner module exposes `scan(adb, iocs, options) -> list[Finding]`."""

from __future__ import annotations

from dataclasses import dataclass

from tvbox_scanner.scanners import crosscheck, device, files, heuristics, network, packages, processes

ALL_SCANNERS = {
    # Known IOCs: the only findings the removal plan acts on.
    "device": device.scan,
    "packages": packages.scan,
    "files": files.scan,
    "processes": processes.scan,
    "network": network.scan,
    # No IOC needed; MEDIUM at most, never removed automatically.
    "heuristics": heuristics.scan,
    "crosscheck": crosscheck.scan,
}


@dataclass
class ScanOptions:
    deep: bool = False  # hash every APK on the device (slow on cheap boxes)
