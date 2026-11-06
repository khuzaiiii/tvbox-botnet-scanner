"""In-memory stand-in for Adb. Maps exact shell commands to canned output."""

from __future__ import annotations


class FakeAdb:
    def __init__(self, responses: dict[str, str], root: bool = False):
        self.responses = responses
        self.root = root
        self.commands: list[str] = []
        self.pulled: list[str] = []
        self.pushed: list[tuple[str, str]] = []

    def root_mode(self) -> str:
        return "adbd" if self.root else "none"

    def has_root(self) -> bool:
        return self.root

    def shell(self, command: str, root: bool = False, check: bool = False) -> str:
        self.commands.append(command)
        return self.responses.get(command, "")

    def run(self, command: str, root: bool = False) -> tuple[int, str]:
        self.commands.append(command)
        out = self.responses.get(command, "")
        return (1 if out.startswith("rc=1") else 0), out

    def devices(self):
        from types import SimpleNamespace
        return [SimpleNamespace(serial="box", state="device"), SimpleNamespace(serial="other", state="unauthorized")]

    def connect(self, host: str) -> str:
        return f"connected to {host}"

    def reboot(self) -> None:
        self.commands.append("<reboot>")

    def push(self, local, remote) -> None:
        self.pushed.append((str(local), remote))

    def pull(self, remote, local) -> None:
        self.pulled.append(remote)
        from pathlib import Path
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        Path(local).write_text(f"backup of {remote}", encoding="utf-8")
