"""Run a remediation plan. Dry-run unless apply=True; backs up before deleting."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from tvbox_scanner.remediation.actions import Action, Risk


@dataclass
class ActionResult:
    action: Action
    status: str  # "dry-run", "done", "skipped", "failed"
    message: str = ""
    output: list[str] = field(default_factory=list)
    backups: list[dict] = field(default_factory=list)  # what was saved, for `restore`


class UnsafeBackupPath(ValueError):
    pass


# Device paths come from an attacker-controlled box (e.g. forged `pm list packages` output),
# so every component is allowlisted before it becomes part of a host path.
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_@+=~,-][A-Za-z0-9._@+=~,-]*$")
_WINDOWS_DEVICE_NAMES = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(10)), *(f"lpt{i}" for i in range(10))}


def safe_backup_path(backup_dir: Path, remote: str) -> tuple[str, Path]:
    """Return (normalized device path, host path inside backup_dir) or raise UnsafeBackupPath."""
    if not remote.startswith("/") or "\x00" in remote:
        raise UnsafeBackupPath(f"refusing to back up {remote!r}: not an absolute device path")
    parts = remote.split("/")[1:]
    for part in parts:
        if (
            not _SAFE_COMPONENT.match(part)
            or part.endswith((".", " "))  # Windows silently strips these, which can turn "..." into ".."
            or part.split(".")[0].lower() in _WINDOWS_DEVICE_NAMES
        ):
            raise UnsafeBackupPath(f"refusing to back up {remote!r}: unsafe path component {part!r}")
    local = backup_dir.joinpath(*parts)
    root = backup_dir.resolve()
    if not local.resolve().is_relative_to(root) or local.resolve() == root:
        raise UnsafeBackupPath(f"refusing to back up {remote!r}: escapes backup directory")
    return "/" + "/".join(parts), local


def _stat(adb, path: str, root: bool) -> dict:
    """Mode/owner/type of a device path, so restore can put it back exactly (a restored
    install-recovery.sh without its exec bit would not fix a bootloop)."""
    out = adb.shell(f"stat -c '%a %u %g %F' '{path}' 2>/dev/null", root=root).split(maxsplit=3)
    if len(out) == 4 and out[0].isdigit() and out[1].isdigit() and out[2].isdigit():
        return {"mode": out[0], "uid": out[1], "gid": out[2], "type": "dir" if "directory" in out[3] else "file"}
    return {}


def _backup(adb, paths: list[str], backup_dir: Path, step: str, root: bool) -> list[dict]:
    # Each step gets its own folder: two steps backing up overlapping paths (an APK, then its
    # whole app dir) would otherwise collide, and `adb pull dir` into an existing dir nests it.
    base = backup_dir / step
    # Validate every path before pulling anything, so a bad entry can't leave a partial backup.
    targets = [safe_backup_path(base, p) for p in paths]
    saved = []
    for remote, local in targets:
        meta = _stat(adb, remote, root)
        if root and adb.root_mode() == "su":
            # adb pull can't read root-only files; stage a copy in /data/local/tmp first.
            staged = f"/data/local/tmp/tvbox_backup_{local.name}"
            adb.shell(f"cp -a '{remote}' '{staged}' && chmod -R a+rX '{staged}'", root=True)
            adb.pull(staged, local)
            adb.shell(f"rm -rf '{staged}'", root=True)
        else:
            adb.pull(remote, local)
        saved.append({"remote": remote, "step": step, "local": local.relative_to(base).as_posix(), **meta})
    return saved


def execute_plan(
    adb,
    plan: list[Action],
    apply: bool = False,
    allow_dangerous: bool = False,
    backup_root: Path = Path("backups"),
    confirm: Callable[[Action], bool] | None = None,
    on_start: Callable[[int, Action], None] | None = None,
    on_result: Callable[[int, ActionResult], None] | None = None,
) -> list[ActionResult]:
    backup_dir = backup_root / time.strftime("%Y%m%d-%H%M%S")
    has_root = adb.has_root()
    results: list[ActionResult] = []

    def record(result: ActionResult) -> None:
        results.append(result)
        if on_result:
            on_result(len(results) - 1, result)

    for action in plan:
        if action.manual_only:
            record(ActionResult(action, "skipped", "manual step"))
            continue
        if action.requires_root and not has_root:
            record(ActionResult(action, "skipped", "needs root"))
            continue
        if action.risk == Risk.DANGEROUS and not allow_dangerous:
            record(ActionResult(action, "skipped", "dangerous; rerun with --allow-system"))
            continue
        if not apply:
            record(ActionResult(action, "dry-run"))
            continue
        if confirm and not confirm(action):
            record(ActionResult(action, "skipped", "declined"))
            continue

        if on_start:
            on_start(len(results), action)
        try:
            step = f"step{len(results):02d}"
            saved = _backup(adb, action.backup_paths, backup_dir, step, action.requires_root) if action.backup_paths else []
            for local, remote in action.uploads:
                adb.push(Path(local), remote)
            outputs = []
            for cmd in action.commands:
                rc, out = adb.run(cmd, root=action.requires_root)
                outputs.append(out)
                # `pm` reports "Failure [...]" with exit code 0 on many builds.
                if rc != 0 or out.startswith(("Failure", "Error")):
                    raise RuntimeError(f"`{cmd}` failed (rc={rc}): {out}")
            record(ActionResult(action, "done", output=outputs, backups=saved))
        except Exception as exc:
            # Stop on failure: later steps (e.g. deleting a package after its process kill
            # failed) may leave the box half-cleaned.
            record(ActionResult(action, "failed", str(exc)))
            break

    if apply:
        backup_dir.mkdir(parents=True, exist_ok=True)
        (backup_dir / "actions.json").write_text(json.dumps(
            [{**r.action.to_dict(), "status": r.status, "message": r.message, "output": r.output,
              "backups": r.backups}
             for r in results], indent=2), encoding="utf-8")
    return results
