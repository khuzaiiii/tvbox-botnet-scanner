"""Running processes whose name or executable matches an IOC."""

from __future__ import annotations

import posixpath

from tvbox_scanner.models import Finding, Severity, TargetType


def list_processes(adb) -> list[tuple[str, str]]:
    """Return [(pid, name)]. Handles both toybox (Android 8+) and old toolbox ps."""
    out = adb.shell("ps -A -o PID,NAME 2>/dev/null", root=adb.has_root())
    if "PID" not in out:
        out = adb.shell("ps", root=adb.has_root())
    procs: list[tuple[str, str]] = []
    lines = out.splitlines()
    if not lines:
        return procs
    header = lines[0].split()
    pid_idx = header.index("PID") if "PID" in header else 1
    for line in lines[1:]:
        parts = line.split()
        if len(parts) > pid_idx:
            procs.append((parts[pid_idx], parts[-1]))
    return procs


def scan(adb, iocs, options) -> list[Finding]:
    procs = list_processes(adb)
    findings = []
    for ioc in iocs:
        wanted = set(ioc.process_names)
        for pid, name in procs:
            if posixpath.basename(name) in wanted:
                findings.append(Finding(
                    scanner="processes",
                    severity=Severity.CRITICAL,
                    title=f"{ioc.family} process running: {name} (pid {pid})",
                    target_type=TargetType.PROCESS,
                    target=pid,
                    family=ioc.family,
                    evidence={"pid": pid, "name": name},
                ))
    return findings
