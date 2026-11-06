"""Thin wrapper around the adb binary.

Everything the scanner knows about a device comes through this class, so tests
can swap in a fake that returns canned output.
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class AdbError(RuntimeError):
    pass


@dataclass
class DeviceInfo:
    serial: str
    state: str


class Adb:
    def __init__(self, serial: str | None = None, adb_path: str = "adb", timeout: int = 60):
        resolved = shutil.which(adb_path)
        if resolved is None:
            raise AdbError(
                f"'{adb_path}' not found. Install Android platform-tools and add it to PATH."
            )
        self.adb_path = resolved
        self.serial = serial
        self.timeout = timeout
        self._root_mode: str | None = None  # "adbd", "su" or "none"

    def _base(self) -> list[str]:
        cmd = [self.adb_path]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd

    def _run(self, args: list[str], check: bool = True) -> str:
        proc = subprocess.run(
            self._base() + args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout,
        )
        if check and proc.returncode != 0:
            raise AdbError(f"adb {' '.join(args)} failed: {proc.stderr.strip() or proc.stdout.strip()}")
        return proc.stdout

    def devices(self) -> list[DeviceInfo]:
        out = subprocess.run(
            [self.adb_path, "devices"], capture_output=True, text=True, timeout=self.timeout
        ).stdout
        result = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                result.append(DeviceInfo(serial=parts[0], state=parts[1]))
        return result

    def root_mode(self) -> str:
        """Detect how (if at all) we can run commands as root."""
        if self._root_mode is None:
            if self._run(["shell", "id -u"], check=False).strip() == "0":
                self._root_mode = "adbd"
            elif self._run(["shell", "su -c 'id -u'"], check=False).strip() == "0":
                self._root_mode = "su"
            else:
                self._root_mode = "none"
        return self._root_mode

    def has_root(self) -> bool:
        return self.root_mode() != "none"

    def shell(self, command: str, root: bool = False, check: bool = False) -> str:
        if root and self.root_mode() == "su":
            command = f"su -c {shlex.quote(command)}"
        return self._run(["shell", command], check=check)

    def run(self, command: str, root: bool = False) -> tuple[int, str]:
        """Run a command and return (exit_code, output).

        adb before Android 7 doesn't forward the remote exit code, so echo it ourselves.
        """
        out = self.shell(f"{command}; echo __RC__$?", root=root)
        body, sep, rc = out.rpartition("__RC__")
        if not sep:
            return 255, out.strip()
        try:
            return int(rc.strip()), body.strip()
        except ValueError:
            return 255, out.strip()

    def connect(self, host: str) -> str:
        """`adb connect host[:port]` for boxes with network ADB enabled."""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*(:\d{1,5})?", host):
            raise AdbError(f"invalid host: {host!r}")
        out = subprocess.run(
            [self.adb_path, "connect", host], capture_output=True, text=True, timeout=self.timeout
        ).stdout.strip()
        if "connected" not in out or "cannot" in out or "failed" in out:
            raise AdbError(out or f"could not connect to {host}")
        return out

    def reboot(self) -> None:
        self._run(["reboot"])

    def push(self, local: Path, remote: str) -> None:
        self._run(["push", str(local), remote])

    def pull(self, remote: str, local: Path) -> None:
        local.parent.mkdir(parents=True, exist_ok=True)
        self._run(["pull", remote, str(local)])
