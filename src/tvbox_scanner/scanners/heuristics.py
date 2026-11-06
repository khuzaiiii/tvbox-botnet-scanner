"""Heuristics: signs that match no known IOC but are worth a look.

Nothing here is rated above MEDIUM. These findings can make the verdict `suspicious`,
never `infected`, and the removal planner ignores them: only known IOCs are removed.
"""

from __future__ import annotations

from tvbox_scanner.models import Finding, Severity, TargetType
from tvbox_scanner.scanners.network import listening_ports

# Executables in these places are writable by any app or by `adb push`: a classic drop spot.
WRITABLE_EXE_DIRS = ("/data/local/tmp/", "/dev/", "/tmp/", "/sdcard/", "/storage/", "/mnt/", "/cache/")
SU_PATHS = ["/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su", "/system/xbin/daemonsu"]
# User-installed apps that legitimately use the com.android.* namespace.
SYSTEM_NAME_ALLOWLIST = {"com.android.chrome"}
ADB_PORT = 5555

PROC_EXE_CMD = 'for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null) && echo "${p#/proc/} $e"; done'


def process_executables(adb, root: bool) -> list[tuple[str, str]]:
    """[(pid, executable path)] for every process whose exe link is readable."""
    result = []
    for line in adb.shell(PROC_EXE_CMD, root=root).splitlines():
        pid, _, exe = line.strip().partition(" ")
        if pid.isdigit() and exe:
            result.append((pid, exe))
    return result


def _suspicious_exe(exe: str) -> str | None:
    if exe.endswith(" (deleted)"):
        return "its executable was deleted from disk after it started (a common way to hide a dropper)"
    if exe.startswith("/memfd:"):
        return "it runs from an in-memory file with no copy on disk"
    if exe.startswith(WRITABLE_EXE_DIRS):
        return "it runs from a folder any app or ADB user can write to"
    return None


def _processes(adb, root: bool) -> list[Finding]:
    findings, seen = [], set()
    for pid, exe in process_executables(adb, root):
        reason = _suspicious_exe(exe)
        if not reason or exe in seen:
            continue
        seen.add(exe)
        findings.append(Finding(
            scanner="heuristics",
            severity=Severity.MEDIUM,
            title=f"Process {pid} runs from an unusual place: {exe}",
            target_type=TargetType.PROCESS,
            target=pid,
            detail=f"Flagged because {reason}. Not a known IOC; look at what it is before acting.",
            evidence={"pid": pid, "exe": exe},
        ))
    return findings


def _packages(adb, iocs) -> list[Finding]:
    known = {p.name for ioc in iocs for p in ioc.packages}
    findings = []
    for line in adb.shell("pm list packages -3").splitlines():
        name = line.strip().removeprefix("package:")
        if not line.strip().startswith("package:") or name in known or name in SYSTEM_NAME_ALLOWLIST:
            continue
        if name.startswith(("com.android.", "android.")):
            findings.append(Finding(
                scanner="heuristics",
                severity=Severity.MEDIUM,
                title=f"User-installed app uses a system-style name: {name}",
                target_type=TargetType.PACKAGE,
                target=name,
                detail="Apps installed by the user don't normally live in the com.android namespace; BADBOX 2.0 "
                       "apps use such names to look like part of Android. Check what the app is.",
            ))
    return findings


def _su_binaries(adb, root: bool) -> list[Finding]:
    present = [p for p in SU_PATHS if adb.shell(f"[ -e '{p}' ] && echo YES", root=root).strip() == "YES"]
    if not present:
        return []
    return [Finding(
        scanner="heuristics",
        severity=Severity.LOW,
        title="Root (su) binary in the firmware: " + ", ".join(present),
        target_type=TargetType.FILE,
        target=present[0],
        detail="Common on cheap boxes, and also how malware such as Vo1d keeps root. Any app may be able to use it.",
        evidence={"paths": present},
    )]


def _proxy(adb) -> list[Finding]:
    values = {key: adb.shell(f"settings get global {key}").strip() for key in ("http_proxy", "global_http_proxy_host")}
    set_values = {k: v for k, v in values.items() if v and v not in ("null", ":0")}
    if not set_values:
        return []
    return [Finding(
        scanner="heuristics",
        severity=Severity.MEDIUM,
        title="System-wide HTTP proxy is set: " + ", ".join(set_values.values()),
        target_type=TargetType.DEVICE,
        target="http_proxy",
        detail="All app traffic goes through this proxy. If nobody set it on purpose, someone can watch or "
               "change that traffic.",
        evidence=set_values,
    )]


def _listening(adb) -> list[Finding]:
    ports = listening_ports(adb)
    findings = []
    if ADB_PORT in ports:
        findings.append(Finding(
            scanner="heuristics",
            severity=Severity.LOW,
            title=f"ADB is open on the network (port {ADB_PORT})",
            target_type=TargetType.NETWORK,
            target=f"0.0.0.0:{ADB_PORT}",
            detail="Expected while you scan over Wi-Fi. Turn network debugging off afterwards: an open ADB port is "
                   "how many boxes get infected.",
            evidence={"port": ADB_PORT},
        ))
    others = sorted(p for p in ports if p != ADB_PORT)
    if others:
        findings.append(Finding(
            scanner="heuristics",
            severity=Severity.LOW,
            title="Listening on all interfaces: TCP " + ", ".join(map(str, others)),
            target_type=TargetType.NETWORK,
            target="listening",
            detail="Other devices on the network can reach these ports. Media apps often do this; a port you can't "
                   "explain is worth a look.",
            evidence={"ports": others},
        ))
    return findings


def scan(adb, iocs, options) -> list[Finding]:
    root = adb.has_root()
    return [
        *_processes(adb, root),
        *_packages(adb, iocs),
        *_su_binaries(adb, root),
        *_proxy(adb),
        *_listening(adb),
    ]
