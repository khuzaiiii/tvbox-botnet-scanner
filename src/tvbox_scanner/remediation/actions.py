from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Risk(IntEnum):
    SAFE = 0      # reversible, no boot impact (disable a user app)
    MODERATE = 1  # reversible with effort (uninstall user app after APK backup)
    DANGEROUS = 2  # touches /system; can bootloop the box


# What an action does, so `restore` knows how to undo it.
KILL = "kill"
DELETE_FILE = "delete_file"
UNINSTALL_USER_APP = "uninstall_user_app"
DISABLE_SYSTEM_APP = "disable_system_app"
DELETE_SYSTEM_APP_DIR = "delete_system_app_dir"
MANUAL = "manual"
# restore-only kinds
RESTORE_FILE = "restore_file"
REINSTALL_APP = "reinstall_app"
ENABLE_SYSTEM_APP = "enable_system_app"


@dataclass
class Action:
    description: str
    commands: list[str]
    risk: Risk
    requires_root: bool = False
    backup_paths: list[str] = field(default_factory=list)  # pulled to the PC before running
    finding_title: str = ""
    manual_only: bool = False  # advice for the user, never executed automatically
    kind: str = MANUAL
    target: str = ""  # package name or device path the action works on
    uploads: list[tuple[str, str]] = field(default_factory=list)  # (local file/dir, device path) pushed first

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "target": self.target,
            "description": self.description,
            "commands": self.commands,
            "risk": self.risk.name,
            "requires_root": self.requires_root,
            "backup_paths": self.backup_paths,
            "finding": self.finding_title,
            "manual_only": self.manual_only,
        }
