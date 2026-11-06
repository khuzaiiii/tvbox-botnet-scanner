"""A simulated infected TV box for recording the demo. Not a real device.

Speaks the same interface as `tvbox_scanner.adb.Adb`, keeps state (killed processes,
deleted files, removed apps) so a rescan after removal shows the difference, and
sleeps a little on slow commands so the scan animation is visible on video.

The indicators are real ones from the shipped IOC files (Dr.Web Vo1d SHA-1,
Deepfield BADBOX 2.0 C2 IP), so the demo exercises the real detection code.
"""

from __future__ import annotations

import socket
import struct
import time
from pathlib import Path
from types import SimpleNamespace

VO1D_SHA1 = "f3732871371819532416cf2ec03ea103a3d61802"  # Dr.Web: Android.Vo1d.1
BADBOX_C2_IP = "172.96.114.6"  # Deepfield: BADBOX 2.0 a1 config node

def _proc_net_hex(ip: str) -> str:
    """IPv4 as /proc/net/tcp prints it (host-order u32 in hex)."""
    return f"{struct.unpack('<I', socket.inet_aton(ip))[0]:08X}"


DELAYS = {  # seconds, so each scan step is visible on video
    "pm list packages -f": 0.9,
    "ps -A -o PID,NAME 2>/dev/null": 0.8,
    "cat /proc/net/tcp 2>/dev/null": 0.7,
}


class DemoBox:
    def __init__(self, speed: float = 1.0):
        self.speed = speed
        self.props = {
            "ro.product.model": "T95 Max",
            "ro.product.manufacturer": "Allwinner",
            "ro.product.board": "exdroid",
            "ro.board.platform": "h616",
            "ro.build.fingerprint": "google/walleye/walleye:10/QP1A.191105.004/test-keys",
            "ro.build.version.release": "10",
            "ro.build.tags": "test-keys",
            "ro.secure": "1",
            "ro.debuggable": "0",
        }
        self.packages = {
            "com.android.settings": "/system/priv-app/Settings/Settings.apk",
            "com.android.tv.launcher": "/system/priv-app/Launcher/Launcher.apk",
            "com.google.android.youtube.tv": "/system/app/YouTube/YouTube.apk",
            "com.google.android.services": "/system/priv-app/GoogleServices/GoogleServices.apk",
            "com.android.tigertv": "/data/app/com.android.tigertv-Xq1/base.apk",
        }
        self.files = {"/system/xbin/vo1d": "file", "/system/xbin/wd": "file", "/data/system/Corejava": "dir"}
        self.procs = {"812": "/system/xbin/vo1d", "813": "/system/xbin/wd"}
        self.c2_connection = True
        self.commands: list[str] = []

    # --- Adb interface --------------------------------------------------------------------

    def root_mode(self) -> str:
        return "su"

    def has_root(self) -> bool:
        return True

    def devices(self):
        return [SimpleNamespace(serial="192.168.1.50:5555", state="device")]

    def connect(self, host: str) -> str:
        return f"connected to {host}"

    def reboot(self) -> None:
        self.commands.append("reboot")

    def pull(self, remote, local) -> None:
        time.sleep(0.25 * self.speed)
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        Path(local).write_text("simulated backup", encoding="utf-8")

    def push(self, local, remote) -> None:
        pass

    def run(self, command: str, root: bool = False) -> tuple[int, str]:
        time.sleep(0.35 * self.speed)
        self.commands.append(command)
        if command.startswith("kill -9"):
            for pid in command.split()[2:]:
                self.procs.pop(pid, None)
            self.c2_connection = False
        elif command.startswith("rm -rf "):
            self.files.pop(command[7:].strip("'"), None)
        elif command.startswith("pm uninstall"):
            self.packages.pop(command.split()[-1], None)
            return 0, "Success"
        return 0, ""

    def shell(self, command: str, root: bool = False, check: bool = False) -> str:
        self.commands.append(command)
        time.sleep(DELAYS.get(command, 0.04) * self.speed)

        if command.startswith("getprop "):
            return self.props.get(command.split()[1], "") + "\n"
        if command == "pm list packages -f":
            return "".join(f"package:{p}={n}\n" for n, p in self.packages.items())
        if command.startswith("[ -"):
            test, path = command[3], command.split("'")[1]
            kind = self.files.get(path)
            ok = kind and (test == "e" or (test == "f" and kind == "file") or (test == "d" and kind == "dir"))
            return "YES\n" if ok else ""
        if command.startswith("sha1sum '/system/xbin/vo1d'") and "/system/xbin/vo1d" in self.files:
            return f"{VO1D_SHA1}  /system/xbin/vo1d\n"
        if command.startswith("stat -c"):
            return "755 0 2000 regular file\n"
        if command == "pm list packages -3":
            return "".join(f"package:{n}\n" for n, p in self.packages.items() if p.startswith("/data/"))
        if command == "ls /proc":
            return "\n".join(["1", "301", "455", *self.procs, "self", "net"]) + "\n"
        if command.startswith("for p in /proc/"):
            exes = {"1": "/system/bin/init", "301": "/system/bin/surfaceflinger", "455": "/system/bin/app_process32"}
            return "".join(f"{pid} {exe}\n" for pid, exe in {**exes, **self.procs}.items())
        if command == "ps -A -o PID,NAME 2>/dev/null":
            base = "  PID NAME\n    1 init\n  301 surfaceflinger\n  455 system_server\n"
            return base + "".join(f"  {pid} {name}\n" for pid, name in self.procs.items())
        if command == "cat /proc/net/tcp 2>/dev/null":
            rows = ("  sl  local_address rem_address   st\n   0: 3201A8C0:9C40 0101A8C0:0035 06 0\n"
                    "   1: 00000000:15B3 00000000:0000 0A 0\n")  # network ADB on 5555, as when scanning over Wi-Fi
            if self.c2_connection:
                rows += f"   1: 3201A8C0:A1F2 {_proc_net_hex(BADBOX_C2_IP)}:0050 01 0\n"
            return rows
        return ""
