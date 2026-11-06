"""Installed packages: match package names, and optionally APK hashes."""

from __future__ import annotations

from tvbox_scanner.models import Finding, Severity, TargetType
from tvbox_scanner.scanners.hashing import device_hashes, match_hash


def list_packages(adb) -> dict[str, str]:
    """Return {package_name: apk_path}."""
    out = adb.shell("pm list packages -f")
    result = {}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        # package:/data/app/com.foo-1/base.apk=com.foo  (path itself may contain '=')
        path, _, name = line[len("package:"):].rpartition("=")
        result[name] = path
    return result


def scan(adb, iocs, options) -> list[Finding]:
    pkgs = list_packages(adb)
    findings = []

    for ioc in iocs:
        for p in ioc.packages:
            if p.name in pkgs:
                findings.append(Finding(
                    scanner="packages",
                    severity=Severity[p.severity],
                    title=f"Known {ioc.family} package installed: {p.name}",
                    target_type=TargetType.PACKAGE,
                    target=p.name,
                    family=ioc.family,
                    detail=p.note,
                    evidence={"path": pkgs[p.name]},
                ))

    if options.deep and any(any(ioc.hashes.values()) for ioc in iocs):
        flagged = {f.target for f in findings}
        for name, path in pkgs.items():
            digests = device_hashes(adb, path)
            family = match_hash(digests, iocs)
            if not family:
                continue
            if name in flagged:
                for f in findings:
                    if f.target == name:
                        f.severity = Severity.CRITICAL
                        f.evidence.update(digests, hash_match=True)
                continue
            findings.append(Finding(
                scanner="packages",
                severity=Severity.CRITICAL,
                title=f"APK hash matches {family}: {name}",
                target_type=TargetType.PACKAGE,
                target=name,
                family=family,
                evidence={"path": path, **digests, "hash_match": True},
            ))

    return findings
