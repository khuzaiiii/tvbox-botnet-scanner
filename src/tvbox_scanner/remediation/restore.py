"""Undo a previous `remove --apply` from its backup folder.

Reads backups/<time>/actions.json and builds a plan that reverses every step that ran,
newest first. The plan goes through the normal executor, so it is a dry run unless
--apply, and /system steps still need --allow-system.

Restoring brings back things that were flagged as malware. It exists to recover from a
removal that broke the box (e.g. a bootloop after deleting install-recovery.sh), not to
second-guess the scan.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from tvbox_scanner.remediation import actions as kinds
from tvbox_scanner.remediation.actions import Action, Risk
from tvbox_scanner.remediation.executor import UnsafeBackupPath, safe_backup_path

FIRMWARE_PREFIXES = ("/system", "/vendor", "/product", "/odm")
_PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
_OCTAL_MODE = re.compile(r"^[0-7]{3,4}$")


class RestoreError(ValueError):
    pass


def _remount(path: str) -> str:
    mount_point = "/" + path.strip("/").split("/")[0]
    return f"mount -o rw,remount {mount_point} 2>/dev/null || mount -o rw,remount /"


def _local_backup(backup_dir: Path, entry: dict) -> tuple[str, Path]:
    step = str(entry.get("step", ""))
    if not re.fullmatch(r"step\d{2,3}", step):
        raise RestoreError(f"backup entry has no valid step folder: {step!r}")
    base = backup_dir / step
    remote, local = safe_backup_path(base, entry.get("remote", ""))
    if entry.get("local") and Path(entry["local"]).as_posix() != local.relative_to(base).as_posix():
        raise RestoreError(f"backup entry for {remote} points somewhere unexpected: {entry['local']!r}")
    if not local.exists():
        raise RestoreError(f"backup file missing on this computer: {local}")
    return remote, local


def _restore_path(backup_dir: Path, entry: dict, index: int, source_title: str) -> Action:
    remote, local = _local_backup(backup_dir, entry)
    staged = f"/data/local/tmp/tvbox_restore_{index}"
    firmware = remote.startswith(FIRMWARE_PREFIXES)
    commands = [_remount(remote)] if firmware else []
    commands += [f"rm -rf '{remote}'", f"cp -a '{staged}' '{remote}'"]
    if _OCTAL_MODE.match(str(entry.get("mode", ""))):
        commands.append(f"chmod {entry['mode']} '{remote}'")
    if str(entry.get("uid", "")).isdigit() and str(entry.get("gid", "")).isdigit():
        commands.append(f"chown {entry['uid']}:{entry['gid']} '{remote}'")
    commands += [f"rm -rf '{staged}'", "sync"]
    return Action(
        description=f"Put back {remote}" + ("" if entry.get("mode") else " (original permissions unknown)"),
        commands=commands,
        risk=Risk.DANGEROUS if firmware else Risk.MODERATE,
        requires_root=True,
        finding_title=source_title,
        kind=kinds.RESTORE_FILE,
        target=remote,
        uploads=[(str(local), staged)],
    )


def build_restore_plan(backup_dir: Path) -> list[Action]:
    log = backup_dir / "actions.json"
    if not log.is_file():
        raise RestoreError(f"{log} not found; pick a folder created by `remove --apply`")
    try:
        entries = json.loads(log.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RestoreError(f"{log} is not valid JSON: {exc}") from exc

    plan: list[Action] = []
    counter = 0
    for entry in reversed(entries):
        if entry.get("status") != "done":
            continue
        kind, target, title = entry.get("kind"), entry.get("target", ""), entry.get("description", "")
        backups = entry.get("backups") or []

        if kind in (kinds.DELETE_FILE, kinds.DELETE_SYSTEM_APP_DIR):
            if not backups:
                raise RestoreError(f"no backup recorded for '{title}'")
            for b in backups:
                plan.append(_restore_path(backup_dir, b, counter, title))
                counter += 1

        elif kind == kinds.UNINSTALL_USER_APP:
            if not _PACKAGE.match(target) or not backups:
                raise RestoreError(f"can't reinstall {target!r}: missing package name or APK backup")
            _, apk = _local_backup(backup_dir, backups[0])
            staged = f"/data/local/tmp/tvbox_restore_{counter}.apk"
            counter += 1
            plan.append(Action(
                description=f"Reinstall {target} (this app was flagged as malware)",
                commands=[f"pm install -r '{staged}'", f"rm -f '{staged}'"],
                risk=Risk.MODERATE,
                finding_title=title,
                kind=kinds.REINSTALL_APP,
                target=target,
                uploads=[(str(apk), staged)],
            ))

        elif kind == kinds.DISABLE_SYSTEM_APP:
            if not _PACKAGE.match(target):
                raise RestoreError(f"bad package name in log: {target!r}")
            plan.append(Action(
                description=f"Re-enable system app {target} for user 0",
                commands=[f"pm install-existing --user 0 {target}", f"pm enable --user 0 {target}"],
                risk=Risk.SAFE,
                finding_title=title,
                kind=kinds.ENABLE_SYSTEM_APP,
                target=target,
            ))

        elif kind in (kinds.RESTORE_FILE, kinds.REINSTALL_APP, kinds.ENABLE_SYSTEM_APP):
            raise RestoreError(f"{backup_dir} is the log of an earlier restore, not a removal backup")

        elif kind in (kinds.KILL, kinds.MANUAL, None):
            continue  # nothing to undo (a killed process restarts on reboot anyway)

        else:
            raise RestoreError(f"unknown action kind in log: {kind!r}")

    if any(a.risk == Risk.DANGEROUS for a in plan):
        plan.append(Action(
            description="Reboot the box after restoring /system files",
            commands=[],
            risk=Risk.SAFE,
            manual_only=True,
        ))
    return plan


__all__ = ["RestoreError", "UnsafeBackupPath", "build_restore_plan"]
