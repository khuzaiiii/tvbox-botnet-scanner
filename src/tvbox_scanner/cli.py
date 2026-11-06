from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tvbox_scanner.adb import Adb, AdbError
from tvbox_scanner.blocklist import export_blocklist
from tvbox_scanner.engine import run_scan
from tvbox_scanner.iocs import DEFAULT_IOC_DIR, load_iocs
from tvbox_scanner.models import Severity
from tvbox_scanner.remediation import Risk, build_plan, execute_plan
from tvbox_scanner.report import format_text, write_html, write_json
from tvbox_scanner.scanners import ALL_SCANNERS, ScanOptions


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tvbox-scan", description="Scan and clean botnet malware on Android TV boxes via ADB.")
    p.add_argument("-s", "--serial", help="adb device serial or ip:port (see `adb devices`)")
    p.add_argument("--adb", default="adb", help="path to adb binary")
    p.add_argument("--ioc-dir", type=Path, default=DEFAULT_IOC_DIR)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("devices", help="list connected devices")
    sub.add_parser("doctor", help="check that Python, adb, the UI extra and IOC files are set up")
    sub.add_parser("version", help="print version")

    scan = sub.add_parser("scan", help="scan the device (read-only)")
    scan.add_argument("--deep", action="store_true", help="hash every APK (slow)")
    scan.add_argument("--only", nargs="+", choices=list(ALL_SCANNERS), help="run only these scanners")
    scan.add_argument("--json", type=Path, help="write JSON report")
    scan.add_argument("--html", type=Path, help="write HTML report")

    rm = sub.add_parser("remove", help="scan, then remediate (dry-run unless --apply)")
    rm.add_argument("--deep", action="store_true")
    rm.add_argument("--apply", action="store_true", help="actually run the commands")
    rm.add_argument("--allow-system", action="store_true", help="allow deleting files in /system (bootloop risk)")
    rm.add_argument("--yes", action="store_true", help="don't ask before each action")
    rm.add_argument("--backup-dir", type=Path, default=Path("backups"))

    rs = sub.add_parser("restore", help="undo a `remove --apply` from its backup folder (dry-run unless --apply)")
    rs.add_argument("backup", type=Path, help="folder created by remove, e.g. backups/20261106-150000")
    rs.add_argument("--apply", action="store_true", help="actually run the commands")
    rs.add_argument("--allow-system", action="store_true", help="allow writing back files in /system")
    rs.add_argument("--yes", action="store_true", help="don't ask before each action")

    ui = sub.add_parser("ui", help="interactive terminal UI (needs the [ui] extra)")
    ui.add_argument("--backup-dir", type=Path, default=Path("backups"))

    bl = sub.add_parser("export-blocklist", help="print C2 domains/IPs for Pi-hole, router or hosts file")
    bl.add_argument("--format", choices=["hosts", "domains", "ips"], default="hosts")
    return p


def _confirm(action) -> bool:
    print(f"\n{action.description}")
    for c in action.commands:
        print(f"  $ {c}")
    for b in action.backup_paths:
        print(f"  backup: {b}")
    for local, remote in action.uploads:
        print(f"  push: {local} -> {remote}")
    return input("Run this? [y/N] ").strip().lower() == "y"


def _print_results(results) -> None:
    print()
    for r in results:
        print(f"[{r.status:8}] {r.action.description}" + (f" ({r.message})" if r.message else ""))
        if r.status == "dry-run":
            for c in r.action.commands:
                print(f"             $ {c}")
            for local, remote in r.action.uploads:
                print(f"             push {local} -> {remote}")


def _restore(adb, args) -> int:
    from tvbox_scanner.remediation.restore import RestoreError, UnsafeBackupPath, build_restore_plan
    try:
        plan = build_restore_plan(args.backup)
    except (RestoreError, UnsafeBackupPath) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not plan:
        print("Nothing to restore: no completed steps in that backup.")
        return 0
    print(f"Restore plan from {args.backup} ({len(plan)} steps). This brings back items that were flagged as malware.")
    if not args.apply:
        print("DRY RUN - nothing will change. Add --apply to execute.")
    results = execute_plan(
        adb, plan,
        apply=args.apply,
        allow_dangerous=args.allow_system,
        backup_root=args.backup / "restore-log",
        confirm=None if args.yes else _confirm,
    )
    _print_results(results)
    return 1 if any(r.status == "failed" for r in results) else 0


def doctor(args) -> int:
    """Setup check meant for humans and AI agents alike. Exit 0 only if scanning can work."""
    ok = True

    def line(status: str, name: str, detail: str) -> None:
        print(f"[{status:4}] {name:10} {detail}")

    v = sys.version_info
    py_ok = v >= (3, 10)
    ok &= py_ok
    line("OK" if py_ok else "FAIL", "python", f"{v.major}.{v.minor}.{v.micro}" + ("" if py_ok else " (need >= 3.10)"))

    try:
        iocs = load_iocs(args.ioc_dir)
        line("OK", "iocs", f"{len(iocs)} families from {args.ioc_dir}")
    except Exception as exc:
        ok = False
        line("FAIL", "iocs", str(exc))

    try:
        import textual
        line("OK", "ui", f"textual {textual.__version__}")
    except ImportError:
        line("WARN", "ui", "textual not installed; `tvbox-scan ui` unavailable (CLI still works)")

    try:
        adb = Adb(adb_path=args.adb)
        line("OK", "adb", adb.adb_path)
    except AdbError as exc:
        line("FAIL", "adb", str(exc))
        return 1

    devices = adb.devices()
    if not devices:
        line("WARN", "devices", "none connected (USB, or `adb connect <ip>:5555`)")
    for d in devices:
        hint = "" if d.state == "device" else "  <- accept 'Allow USB debugging' on the TV"
        line("OK" if d.state == "device" else "WARN", "device", f"{d.serial} {d.state}{hint}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "version":
        from tvbox_scanner import __version__
        print(__version__)
        return 0
    if args.command == "doctor":
        return doctor(args)
    iocs = load_iocs(args.ioc_dir)

    if args.command == "export-blocklist":
        sys.stdout.write(export_blocklist(iocs, args.format))
        return 0

    if args.command == "ui":
        try:
            from tvbox_scanner.ui.app import run_ui
        except ImportError:
            print("The UI needs Textual. Reinstall with the [ui] extra (see AGENTS.md).", file=sys.stderr)
            return 2
        try:
            Adb(adb_path=args.adb)  # fail fast if adb is missing
        except AdbError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return run_ui(lambda serial: Adb(serial=serial, adb_path=args.adb), iocs, args.serial, args.backup_dir)

    try:
        adb = Adb(serial=args.serial, adb_path=args.adb)
        if args.command == "devices":
            for d in adb.devices():
                print(f"{d.serial}\t{d.state}")
            return 0

        if args.command == "restore":
            return _restore(adb, args)

        result = run_scan(adb, iocs, ScanOptions(deep=args.deep), getattr(args, "only", None))
        print(format_text(result))

        if args.command == "scan":
            if args.json:
                write_json(result, args.json)
            if args.html:
                write_html(result, args.html)
            return 1 if result.findings and max(f.severity for f in result.findings) >= Severity.HIGH else 0

        plan = build_plan(result)
        if not plan:
            print("\nNothing to remove.")
            return 0
        if not args.apply:
            print("\nDRY RUN - nothing will change. Add --apply to execute.")
        if any(a.risk == Risk.DANGEROUS for a in plan) and not args.allow_system:
            print("Some steps modify /system and are skipped. Add --allow-system to include them (bootloop risk).")

        results = execute_plan(
            adb, plan,
            apply=args.apply,
            allow_dangerous=args.allow_system,
            backup_root=args.backup_dir,
            confirm=None if args.yes else _confirm,
        )
        _print_results(results)
        return 1 if any(r.status == "failed" for r in results) else 0

    except AdbError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
