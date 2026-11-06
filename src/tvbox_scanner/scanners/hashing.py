"""Hash files on the device with whatever the box's toybox/busybox offers."""

from __future__ import annotations

from tvbox_scanner.iocs import HASH_LENGTHS


def device_hashes(adb, path: str, root: bool = False, algos: tuple[str, ...] = ("sha1", "sha256")) -> dict[str, str]:
    """Return {"sha1": ..., "sha256": ...} for the algorithms the device supports."""
    out = {}
    for algo in algos:
        line = adb.shell(f"{algo}sum '{path}' 2>/dev/null", root=root).split()
        if line and len(line[0]) == HASH_LENGTHS[algo]:
            out[algo] = line[0].lower()
    return out


def match_hash(digests: dict[str, str], iocs) -> str | None:
    """Return the family whose hash list contains any of the digests."""
    for ioc in iocs:
        for algo, value in digests.items():
            if value in ioc.hashes.get(algo, ()):
                return ioc.family
    return None
