"""Turn findings into an ordered list of remediation actions.

Order matters: kill processes first (so watchdogs can't respawn files), then
remove files, then packages. Network findings only produce advice.
"""

from __future__ import annotations

import posixpath

from tvbox_scanner.models import Finding, ScanResult, Severity, TargetType
from tvbox_scanner.remediation import actions as kinds
from tvbox_scanner.remediation.actions import Action, Risk

ORDER = [TargetType.PROCESS, TargetType.FILE, TargetType.PACKAGE, TargetType.NETWORK]


def _remount_cmd(path: str) -> str:
    # System-as-root devices mount / not /system; try both.
    mount_point = "/" + path.strip("/").split("/")[0]
    return f"mount -o rw,remount {mount_point} 2>/dev/null || mount -o rw,remount / "


def _plan_processes(found: list[Finding]) -> Action:
    # One kill for all pids: killing them one by one gives watchdogs (Vo1d `wd`) time to respawn the rest.
    names = ", ".join(f"{f.evidence.get('name')} (pid {f.target})" for f in found)
    return Action(
        description=f"Kill {names}",
        commands=[f"kill -9 {' '.join(f.target for f in found)}"],
        risk=Risk.MODERATE,
        requires_root=True,
        finding_title="; ".join(f.title for f in found),
        kind=kinds.KILL,
    )


def _plan_file(f: Finding) -> Action:
    path = f.target
    if f.in_firmware:
        return Action(
            description=f"Delete firmware file {path}",
            commands=[_remount_cmd(path), f"rm -rf '{path}'", "sync"],
            risk=Risk.DANGEROUS,
            requires_root=True,
            backup_paths=[path],
            finding_title=f.title,
            kind=kinds.DELETE_FILE,
            target=path,
        )
    return Action(
        description=f"Delete {path}",
        commands=[f"rm -rf '{path}'"],
        risk=Risk.MODERATE,
        requires_root=path.startswith("/data/system"),
        backup_paths=[path],
        finding_title=f.title,
        kind=kinds.DELETE_FILE,
        target=path,
    )


def _plan_package(f: Finding) -> list[Action]:
    pkg = f.target
    apk = f.evidence.get("path", "")
    if apk.startswith("/data/"):
        return [Action(
            description=f"Uninstall user app {pkg}",
            commands=[f"pm uninstall {pkg}"],
            risk=Risk.MODERATE,
            backup_paths=[apk],
            finding_title=f.title,
            kind=kinds.UNINSTALL_USER_APP,
            target=pkg,
        )]
    # Preinstalled in firmware: hide it for user 0 (reversible), then optionally delete from /system.
    actions = [Action(
        description=f"Disable and remove system app {pkg} for user 0 (APK stays in firmware)",
        commands=[f"pm disable-user --user 0 {pkg}", f"pm uninstall -k --user 0 {pkg}"],
        risk=Risk.SAFE,
        backup_paths=[apk] if apk else [],
        finding_title=f.title,
        kind=kinds.DISABLE_SYSTEM_APP,
        target=pkg,
    )]
    if apk:
        app_dir = posixpath.dirname(apk)
        actions.append(Action(
            description=f"Delete {app_dir} from firmware",
            commands=[_remount_cmd(app_dir), f"rm -rf '{app_dir}'", "sync"],
            risk=Risk.DANGEROUS,
            requires_root=True,
            backup_paths=[app_dir],
            finding_title=f.title,
            kind=kinds.DELETE_SYSTEM_APP_DIR,
            target=app_dir,
        ))
    return actions


def _plan_network(f: Finding) -> Action:
    return Action(
        description=f"Block {f.evidence.get('ip')} at router/firewall and DNS-sinkhole {f.family} domains "
                    "(run: tvbox-scan export-blocklist)",
        commands=[],
        risk=Risk.SAFE,
        finding_title=f.title,
        manual_only=True,
    )


def build_plan(result: ScanResult, min_severity: Severity = Severity.HIGH) -> list[Action]:
    targets = [f for f in result.findings if f.severity >= min_severity]
    targets.sort(key=lambda f: ORDER.index(f.target_type) if f.target_type in ORDER else 99)

    plan: list[Action] = []
    procs = [f for f in targets if f.target_type == TargetType.PROCESS]
    if procs:
        plan.append(_plan_processes(procs))
    seen_net: set[str] = set()
    for f in targets:
        if f.target_type == TargetType.FILE:
            plan.append(_plan_file(f))
        elif f.target_type == TargetType.PACKAGE:
            plan.extend(_plan_package(f))
        elif f.target_type == TargetType.NETWORK and f.evidence.get("ip") not in seen_net:
            seen_net.add(f.evidence.get("ip"))
            plan.append(_plan_network(f))

    if any(a.risk == Risk.DANGEROUS for a in plan):
        plan.append(Action(
            description="Reboot, then run `tvbox-scan scan` again. If the files come back, the "
                        "infection is in a partition this tool can't clean: reflash stock/clean firmware "
                        "or replace the box.",
            commands=[],
            risk=Risk.SAFE,
            manual_only=True,
        ))
    return plan
