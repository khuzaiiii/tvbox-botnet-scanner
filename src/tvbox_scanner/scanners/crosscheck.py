"""Cross-checks: ask the box the same question two ways and flag disagreement.

Malware with root can make `ps` or `pm` lie. It rarely patches every other way of
reading the same state, so a process in /proc that `ps` doesn't show, or a package in
packages.xml that `pm` doesn't list, is a sign something is hiding. Rated MEDIUM:
these never enter the removal plan, which only acts on known IOCs.
"""

from __future__ import annotations

import re

from tvbox_scanner.models import Finding, Severity, TargetType
from tvbox_scanner.scanners.processes import list_processes

# If more than this share of /proc is "hidden", ps output was unreadable rather than lying.
MAX_HIDDEN_SHARE = 0.5
PACKAGES_XML = "/data/system/packages.xml"
# Android 12+ stores packages.xml in binary ABX; abx2xml (on the box) converts it back.
PACKAGES_XML_CMD = f"abx2xml {PACKAGES_XML} - 2>/dev/null || cat {PACKAGES_XML} 2>/dev/null"
_PACKAGE_TAG = re.compile(r'<package\s[^>]*?\bname="([A-Za-z0-9_.]+)"')


class CrossCheckError(RuntimeError):
    pass


def proc_pids(adb, root: bool) -> set[str]:
    return {entry for entry in adb.shell("ls /proc", root=root).split() if entry.isdigit()}


def hidden_processes(adb, root: bool) -> list[tuple[str, str]]:
    """[(pid, comm)] present in /proc before and after `ps`, but missing from `ps`."""
    before = proc_pids(adb, root)
    shown = {pid for pid, _ in list_processes(adb)}
    after = proc_pids(adb, root)
    if not before or not shown:
        return []
    stable = before & after  # alive across the whole `ps` call, so `ps` should have seen it
    hidden = sorted(stable - shown, key=int)
    if len(hidden) > MAX_HIDDEN_SHARE * len(stable):
        raise CrossCheckError(f"`ps` listed {len(shown)} processes but /proc has {len(stable)}; "
                              "ps output not understood, process cross-check skipped")
    result = []
    for pid in hidden:  # pid is all digits, safe to put in a command
        comm = adb.shell(f"cat /proc/{pid}/comm 2>/dev/null", root=root).strip()
        if comm:  # empty: exited in the meantime
            result.append((pid, comm))
    return result


def hidden_packages(adb) -> list[str]:
    """Packages recorded in packages.xml that `pm` doesn't list, even with -u (uninstalled)."""
    xml = adb.shell(PACKAGES_XML_CMD, root=True)
    in_xml = set(_PACKAGE_TAG.findall(xml))
    listed = {line.strip()[len("package:"):] for line in adb.shell("pm list packages -u").splitlines()
              if line.strip().startswith("package:")}
    if not in_xml or not listed:
        return []
    return sorted(in_xml - listed)


def scan(adb, iocs, options) -> list[Finding]:
    root = adb.has_root()
    findings = []
    for pid, comm in hidden_processes(adb, root):
        findings.append(Finding(
            scanner="crosscheck",
            severity=Severity.MEDIUM,
            title=f"Process hidden from ps: {comm} (pid {pid})",
            target_type=TargetType.PROCESS,
            target=pid,
            detail="It exists in /proc but `ps` did not list it. Rootkits hide processes this way.",
            evidence={"pid": pid, "name": comm},
        ))
    if root:  # packages.xml is root-only
        for name in hidden_packages(adb):
            findings.append(Finding(
                scanner="crosscheck",
                severity=Severity.MEDIUM,
                title=f"Package hidden from pm: {name}",
                target_type=TargetType.PACKAGE,
                target=name,
                detail=f"Listed in {PACKAGES_XML} but `pm list packages -u` doesn't show it.",
                evidence={"source": PACKAGES_XML},
            ))
    return findings
