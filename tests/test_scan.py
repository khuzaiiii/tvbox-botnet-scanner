import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_adb import FakeAdb  # noqa: E402
from tvbox_scanner.blocklist import export_blocklist  # noqa: E402
from tvbox_scanner.engine import run_scan  # noqa: E402
from tvbox_scanner.iocs import IocSet, load_iocs  # noqa: E402
from tvbox_scanner.models import Verdict  # noqa: E402
from tvbox_scanner.remediation import Risk, build_plan, execute_plan  # noqa: E402
from tvbox_scanner.scanners.network import remote_endpoints  # noqa: E402
from tvbox_scanner.scanners.packages import list_packages  # noqa: E402

TEST_IOC = IocSet.from_dict({
    "family": "TestFam",
    "packages": ["com.evil.sdk", "com.evil.system"],
    "files": [
        {"path": "/system/xbin/vo1d", "severity": "CRITICAL"},
        {"path": "/system/bin/install-recovery.sh", "severity": "HIGH", "content_markers": ["vo1d"]},
        {"path": "/data/system/Corejava", "severity": "HIGH"},
    ],
    "process_names": ["vo1d"],
    "ips": ["1.2.3.4"],
    "domains": ["Evil.Example"],
    "device_models": ["T95"],
})

INFECTED = {
    "getprop ro.product.model": "T95 Max\n",
    "getprop ro.build.tags": "test-keys\n",
    "pm list packages -f": (
        "package:/data/app/com.evil.sdk-1/base.apk=com.evil.sdk\n"
        "package:/system/priv-app/Evil/Evil.apk=com.evil.system\n"
        "package:/system/app/Settings/Settings.apk=com.android.settings\n"
    ),
    "[ -e '/system/xbin/vo1d' ] && echo YES": "YES\n",
    "[ -e '/system/bin/install-recovery.sh' ] && echo YES": "YES\n",
    "cat '/system/bin/install-recovery.sh' 2>/dev/null": "#!/system/bin/sh\n/system/xbin/vo1d &\n",
    "ps -A -o PID,NAME 2>/dev/null": "  PID NAME\n    1 init\n  812 /system/xbin/vo1d\n",
    # 1.2.3.4:443 = 04030201:01BB in little-endian /proc/net/tcp format
    "cat /proc/net/tcp 2>/dev/null": (
        "  sl  local_address rem_address   st\n"
        "   0: 0100007F:1F90 04030201:01BB 01 0000\n"
        "   1: 0100007F:1F91 08080808:0035 06 0000\n"
    ),
}


class ScanTests(unittest.TestCase):
    def test_list_packages_parses_paths_with_equals(self):
        adb = FakeAdb({"pm list packages -f": "package:/data/app/a==/base.apk=com.a\n"})
        self.assertEqual(list_packages(adb), {"com.a": "/data/app/a==/base.apk"})

    def test_tcp_decode(self):
        eps = remote_endpoints(FakeAdb(INFECTED))
        self.assertEqual(eps, [("1.2.3.4", 443, "ESTABLISHED")])

    def test_infected_box(self):
        result = run_scan(FakeAdb(INFECTED, root=True), [TEST_IOC])
        titles = " | ".join(f.title for f in result.findings)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.verdict, Verdict.INFECTED_FIRMWARE)
        for expected in ("com.evil.sdk", "com.evil.system", "/system/xbin/vo1d",
                         "install-recovery.sh", "pid 812", "1.2.3.4", "T95", "test-keys"):
            self.assertIn(expected, titles)
        self.assertNotIn("Corejava", titles)

    def test_content_marker_required(self):
        responses = dict(INFECTED)
        responses["cat '/system/bin/install-recovery.sh' 2>/dev/null"] = "#!/system/bin/sh\necho stock\n"
        result = run_scan(FakeAdb(responses), [TEST_IOC], only=["files"])
        self.assertFalse(any("install-recovery" in f.title for f in result.findings))

    def test_clean_box_is_not_called_clean(self):
        result = run_scan(FakeAdb({}), [TEST_IOC])
        self.assertEqual(result.verdict, Verdict.NO_IOC_MATCH)

    def test_plan_order_and_risk(self):
        result = run_scan(FakeAdb(INFECTED, root=True), [TEST_IOC])
        plan = build_plan(result)
        self.assertTrue(plan[0].description.startswith("Kill"))
        user_app = next(a for a in plan if "com.evil.sdk" in a.description)
        self.assertEqual(user_app.commands, ["pm uninstall com.evil.sdk"])
        sys_app = next(a for a in plan if "com.evil.system" in a.description)
        self.assertEqual(sys_app.risk, Risk.SAFE)
        self.assertIn("pm uninstall -k --user 0 com.evil.system", sys_app.commands)
        self.assertTrue(any(a.risk == Risk.DANGEROUS for a in plan))
        self.assertTrue(plan[-1].manual_only)

    def test_dry_run_changes_nothing(self):
        adb = FakeAdb(INFECTED, root=True)
        plan = build_plan(run_scan(adb, [TEST_IOC]))
        before = len(adb.commands)
        results = execute_plan(adb, plan, apply=False)
        self.assertEqual(len(adb.commands), before)
        self.assertTrue(all(r.status in ("dry-run", "skipped") for r in results))

    def test_apply_skips_system_without_flag_and_backs_up(self):
        adb = FakeAdb(INFECTED, root=True)
        plan = build_plan(run_scan(adb, [TEST_IOC]))
        with tempfile.TemporaryDirectory() as tmp:
            results = execute_plan(adb, plan, apply=True, backup_root=Path(tmp))
        self.assertIn("pm uninstall com.evil.sdk", adb.commands)
        self.assertNotIn("rm -rf '/system/xbin/vo1d'", adb.commands)
        self.assertIn("/data/app/com.evil.sdk-1/base.apk", adb.pulled)
        self.assertTrue(any(r.message.startswith("dangerous") for r in results))

    def test_no_root_skips_root_actions(self):
        adb = FakeAdb(INFECTED, root=False)
        plan = build_plan(run_scan(adb, [TEST_IOC]))
        with tempfile.TemporaryDirectory() as tmp:
            results = execute_plan(adb, plan, apply=True, allow_dangerous=True, backup_root=Path(tmp))
        kill = next(r for r in results if r.action.description.startswith("Kill"))
        self.assertEqual(kill.message, "needs root")

    def test_pm_failure_is_reported_and_stops_plan(self):
        responses = dict(INFECTED)
        responses["pm uninstall com.evil.sdk"] = "Failure [DELETE_FAILED_INTERNAL_ERROR]"
        adb = FakeAdb(responses, root=True)
        plan = build_plan(run_scan(adb, [TEST_IOC]))
        with tempfile.TemporaryDirectory() as tmp:
            results = execute_plan(adb, plan, apply=True, backup_root=Path(tmp))
        failed = [r for r in results if r.status == "failed"]
        self.assertEqual(len(failed), 1)
        self.assertIn("com.evil.sdk", failed[0].message)
        self.assertIs(results[-1], failed[0])  # nothing ran after the failure

    def test_forged_apk_path_cannot_escape_backup_dir(self):
        # Malware with root forges `pm list packages -f` to point the backup outside backups/.
        evil = "/data/app/" + "../" * 12 + "Users/Public/PWNED.bat"
        responses = dict(INFECTED)
        responses["pm list packages -f"] = f"package:{evil}=com.evil.sdk\n"
        adb = FakeAdb(responses, root=True)
        plan = build_plan(run_scan(adb, [TEST_IOC]))
        with tempfile.TemporaryDirectory() as tmp:
            results = execute_plan(adb, plan, apply=True, backup_root=Path(tmp))
        failed = [r for r in results if r.status == "failed"]
        self.assertEqual(len(failed), 1)
        self.assertIn("unsafe path component", failed[0].message)
        self.assertNotIn(evil, adb.pulled)
        self.assertNotIn("pm uninstall com.evil.sdk", adb.commands)  # nothing deleted without a backup

    def test_safe_backup_path_rules(self):
        from tvbox_scanner.remediation.executor import UnsafeBackupPath, safe_backup_path
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ok = "/data/app/~~Ab12==/com.evil-Xy==/base.apk"
            remote, local = safe_backup_path(base, ok)
            self.assertEqual(remote, ok)
            self.assertTrue(local.resolve().is_relative_to(base.resolve()))
            for bad in [
                "data/app/x.apk",               # relative
                "/data/app/../../etc/passwd",   # traversal
                "/data/app/.../x",              # Windows strips trailing dots
                "/data/app/x./y",
                "/data/app/C:/Windows/x",       # drive / alternate data stream
                "/data/app/a\\..\\..\\x",       # backslash separators
                "/data/app/CON/x",              # Windows device name
                "/data/app/nul.apk",
                "/data//app/x",                 # empty component
                "/",
            ]:
                with self.assertRaises(UnsafeBackupPath, msg=bad):
                    safe_backup_path(base, bad)

    def test_sha1_file_hash_match_is_critical(self):
        ioc = IocSet.from_dict({
            "family": "H",
            "files": [{"path": "/system/xbin/x", "severity": "HIGH", "kind": "file"}],
            "sha1": ["A" * 40],
        })
        adb = FakeAdb({
            "[ -f '/system/xbin/x' ] && echo YES": "YES",
            "sha1sum '/system/xbin/x' 2>/dev/null": "a" * 40 + "  /system/xbin/x",
        })
        [f] = run_scan(adb, [ioc], only=["files"]).findings
        self.assertEqual(f.severity.name, "CRITICAL")
        self.assertTrue(f.evidence["hash_match"])

    def test_vaccinated_corejava_is_not_flagged(self):
        # T95 cleanup replaces the Corejava dir with a locked empty file.
        ioc = IocSet.from_dict({"family": "T", "files": [{"path": "/data/system/Corejava", "kind": "dir"}]})
        vaccinated = FakeAdb({"[ -e '/data/system/Corejava' ] && echo YES": "YES"}, root=True)
        self.assertEqual(run_scan(vaccinated, [ioc], only=["files"]).findings, [])
        infected = FakeAdb({"[ -d '/data/system/Corejava' ] && echo YES": "YES"}, root=True)
        self.assertEqual(len(run_scan(infected, [ioc], only=["files"]).findings), 1)

    def test_package_entry_with_severity_and_note(self):
        ioc = IocSet.from_dict({"family": "P", "packages": [{"name": "com.x", "severity": "CRITICAL", "note": "n"}]})
        adb = FakeAdb({"pm list packages -f": "package:/data/app/com.x-1/base.apk=com.x\n"})
        [f] = run_scan(adb, [ioc], only=["packages"]).findings
        self.assertEqual((f.severity.name, f.detail), ("CRITICAL", "n"))

    def test_deep_scan_apk_sha256(self):
        ioc = IocSet.from_dict({"family": "B", "sha256": ["b" * 64]})
        from tvbox_scanner.scanners import ScanOptions
        adb = FakeAdb({
            "pm list packages -f": "package:/data/app/com.iptv-1/base.apk=com.iptv\n",
            "sha256sum '/data/app/com.iptv-1/base.apk' 2>/dev/null": "b" * 64 + "  base.apk",
        })
        [f] = run_scan(adb, [ioc], ScanOptions(deep=True), only=["packages"]).findings
        self.assertEqual((f.target, f.severity.name), ("com.iptv", "CRITICAL"))

    def test_model_match_is_whole_word(self):
        ioc = IocSet.from_dict({"family": "M", "device_models": ["Q9", "T95", "T95MAX"]})
        for model, hits in [("TQ95", 0), ("Q9 Pro", 1), ("T95 Max", 1), ("T95MAX", 1)]:
            adb = FakeAdb({"getprop ro.product.model": model})
            found = [f for f in run_scan(adb, [ioc], only=["device"]).findings if "known-affected" in f.title]
            self.assertEqual(len(found), hits, model)

    def test_invalid_hash_rejected(self):
        with self.assertRaises(ValueError):
            IocSet.from_dict({"family": "X", "sha1": ["not-a-hash"]})

    def test_shipped_iocs_are_well_formed(self):
        sets = load_iocs()
        self.assertEqual({s.family for s in sets} >= {"Vo1d", "Pandora", "BADBOX 2.0", "T95-Corejava (BADBOX 1)"}, True)
        for s in sets:
            self.assertTrue(s.sources, s.family)
            for d in s.domains:
                self.assertNotIn("[", d)
                self.assertNotIn("/", d)
            for name in s.process_names:
                self.assertGreaterEqual(len(name), 2)

    def _removed_box(self, tmp):
        responses = dict(INFECTED)
        responses["stat -c '%a %u %g %F' '/system/bin/install-recovery.sh' 2>/dev/null"] = "755 0 2000 regular file"
        adb = FakeAdb(responses, root=True)
        plan = build_plan(run_scan(adb, [TEST_IOC]))
        execute_plan(adb, plan, apply=True, allow_dangerous=True, backup_root=Path(tmp))
        [backup_dir] = [p for p in Path(tmp).iterdir() if p.is_dir()]
        return backup_dir

    def test_restore_round_trip(self):
        from tvbox_scanner.remediation import actions as kinds
        from tvbox_scanner.remediation.restore import build_restore_plan
        with tempfile.TemporaryDirectory() as tmp:
            backup_dir = self._removed_box(tmp)
            plan = build_restore_plan(backup_dir)
            by_kind = {}
            for a in plan:
                by_kind.setdefault(a.kind, []).append(a)
            # reversed order: last removal step is restored first
            self.assertEqual(plan[0].kind, kinds.RESTORE_FILE)  # /system/priv-app/Evil dir
            self.assertIn(kinds.REINSTALL_APP, by_kind)
            self.assertIn(kinds.ENABLE_SYSTEM_APP, by_kind)
            rec = next(a for a in by_kind[kinds.RESTORE_FILE] if a.target == "/system/bin/install-recovery.sh")
            self.assertIn("chmod 755 '/system/bin/install-recovery.sh'", rec.commands)
            self.assertIn("chown 0:2000 '/system/bin/install-recovery.sh'", rec.commands)
            self.assertEqual(rec.risk, Risk.DANGEROUS)
            self.assertNotIn(kinds.KILL, by_kind)

            adb = FakeAdb({}, root=True)
            results = execute_plan(adb, plan, apply=True, allow_dangerous=True,
                                   backup_root=backup_dir / "restore-log")
            self.assertFalse([r for r in results if r.status == "failed"])
            self.assertIn("pm enable --user 0 com.evil.system", adb.commands)
            self.assertTrue(any(remote.endswith(".apk") for _, remote in adb.pushed))

    def test_restore_rejects_tampered_log(self):
        import json

        from tvbox_scanner.remediation.executor import UnsafeBackupPath
        from tvbox_scanner.remediation.restore import RestoreError, build_restore_plan
        with tempfile.TemporaryDirectory() as tmp:
            backup_dir = self._removed_box(tmp)
            log = backup_dir / "actions.json"
            entries = json.loads(log.read_text(encoding="utf-8"))
            for e in entries:
                for b in e.get("backups", []):
                    b["remote"] = "/data/app/../../../../x"
            log.write_text(json.dumps(entries), encoding="utf-8")
            with self.assertRaises((RestoreError, UnsafeBackupPath)):
                build_restore_plan(backup_dir)

    def test_restore_refuses_restore_log(self):
        from tvbox_scanner.remediation.restore import RestoreError, build_restore_plan
        with tempfile.TemporaryDirectory() as tmp:
            backup_dir = self._removed_box(tmp)
            plan = build_restore_plan(backup_dir)
            execute_plan(FakeAdb({}, root=True), plan, apply=True, allow_dangerous=True,
                         backup_root=backup_dir / "restore-log")
            [log_dir] = list((backup_dir / "restore-log").iterdir())
            with self.assertRaises(RestoreError):
                build_restore_plan(log_dir)

    def test_blocklist(self):
        self.assertEqual(export_blocklist([TEST_IOC], "hosts"), "0.0.0.0 evil.example\n")

    def test_shipped_ioc_files_load(self):
        families = [i.family for i in load_iocs()]
        self.assertIn("Vo1d", families)


if __name__ == "__main__":
    unittest.main()
