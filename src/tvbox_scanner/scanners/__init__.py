"""Each scanner module exposes `scan(adb, iocs, options) -> list[Finding]`."""

from __future__ import annotations

from dataclasses import dataclass

from tvbox_scanner.scanners import device, files, network, packages, processes

ALL_SCANNERS = {
    "device": device.scan,
    "packages": packages.scan,
    "files": files.scan,
    "processes": processes.scan,
    "network": network.scan,
}


@dataclass
class ScanOptions:
    deep: bool = False  # hash every APK on the device (slow on cheap boxes)
