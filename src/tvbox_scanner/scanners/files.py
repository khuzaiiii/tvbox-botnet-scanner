"""Filesystem IOCs: dropped binaries, modified boot scripts, payload folders."""

from __future__ import annotations

from tvbox_scanner.models import Finding, Severity, TargetType
from tvbox_scanner.scanners.hashing import device_hashes

KIND_TEST = {"any": "-e", "file": "-f", "dir": "-d"}


def scan(adb, iocs, options) -> list[Finding]:
    root = adb.has_root()
    findings = []

    for ioc in iocs:
        for f in ioc.files:
            # /data/system is unreadable without root; a miss there means "unknown", not "absent".
            test = KIND_TEST[f.kind]
            exists = adb.shell(f"[ {test} '{f.path}' ] && echo YES", root=root).strip() == "YES"
            if not exists:
                continue

            evidence: dict = {"path": f.path}
            if f.kind != "dir":
                evidence.update(device_hashes(adb, f.path, root=root))

            if f.content_markers:
                content = adb.shell(f"cat '{f.path}' 2>/dev/null", root=root)
                hits = [m for m in f.content_markers if m in content]
                if not hits:
                    continue
                evidence["markers"] = hits

            severity = Severity[f.severity]
            if any(evidence.get(algo) in ioc.hashes[algo] for algo in ioc.hashes):
                severity = Severity.CRITICAL
                evidence["hash_match"] = True

            findings.append(Finding(
                scanner="files",
                severity=severity,
                title=f"{ioc.family} file present: {f.path}",
                target_type=TargetType.FILE,
                target=f.path,
                family=ioc.family,
                detail=f.note,
                evidence=evidence,
            ))

    return findings
