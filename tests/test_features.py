"""Heuristics, cross-checks, DNS, compare, redaction, multi-device scan, i18n, executor failures."""

import contextlib
import importlib
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_adb import FakeAdb  # noqa: E402
from test_scan import INFECTED, TEST_IOC  # noqa: E402
from tvbox_scanner import cli, i18n  # noqa: E402
from tvbox_scanner.compare import compare, format_comparison  # noqa: E402
from tvbox_scanner.engine import run_scan  # noqa: E402
from tvbox_scanner.models import Severity, Verdict  # noqa: E402
from tvbox_scanner.remediation import Action, Risk, build_plan, execute_plan  # noqa: E402
from tvbox_scanner.report.redact import redacted  # noqa: E402
from tvbox_scanner.scanners.crosscheck import PACKAGES_XML_CMD  # noqa: E402
from tvbox_scanner.scanners.heuristics import PROC_EXE_CMD  # noqa: E402

PS = "ps -A -o PID,NAME 2>/dev/null"


def tcp_row(local: str, remote: str, state: str) -> str:
    return f"   0: {local} {remote} {state} 0\n"


class HeuristicTests(unittest.TestCase):
    def scan(self, responses, root=True):
        return run_scan(FakeAdb(responses, root=root), [TEST_IOC], only=["heuristics"])

    def test_process_exe_locations(self):
        result = self.scan({PROC_EXE_CMD: (
            "1 /system/bin/init\n"
            "200 /data/local/tmp/.x (deleted)\n"
            "201 /memfd:jit (deleted)\n"
            "202 /data/local/tmp/miner\n"
            "203 /data/local/tmp/miner\n"  # same exe twice: one finding
            "garbage line\n"
        )})
        titles = [f.title for f in result.findings]
        self.assertEqual(len(titles), 3, titles)
        self.assertTrue(all(f.severity == Severity.MEDIUM for f in result.findings))
        self.assertEqual(result.verdict, Verdict.SUSPICIOUS)

    def test_heuristics_never_enter_the_removal_plan(self):
        result = self.scan({
            PROC_EXE_CMD: "200 /data/local/tmp/x\n",
            "pm list packages -3": "package:com.android.fakeupdate\n",
            "settings get global http_proxy": "10.0.0.9:8080\n",
        })
        self.assertTrue(result.findings)
        self.assertEqual(build_plan(result), [])

    def test_system_style_names_of_user_apps(self):
        result = self.scan({"pm list packages -3": (
            "package:com.android.fakeupdate\n"
            "package:com.android.chrome\n"       # allowlisted
            "package:com.evil.sdk\n"             # IOC package: the packages scanner reports it
            "package:com.netflix.ninja\n"
        )})
        self.assertEqual([f.target for f in result.findings], ["com.android.fakeupdate"])

    def test_proxy_and_listening_ports(self):
        result = self.scan({
            "settings get global http_proxy": "null\n",
            "settings get global global_http_proxy_host": "10.0.0.9\n",
            "cat /proc/net/tcp 2>/dev/null": "  sl local rem st\n"
                + tcp_row("00000000:15B3", "00000000:0000", "0A")    # 0.0.0.0:5555
                + tcp_row("00000000:1F90", "00000000:0000", "0A")    # 0.0.0.0:8080
                + tcp_row("0100007F:1F91", "00000000:0000", "0A"),   # 127.0.0.1 only: ignored
        })
        titles = " | ".join(f.title for f in result.findings)
        self.assertIn("proxy", titles)
        self.assertIn("5555", titles)
        self.assertIn("TCP 8080", titles)
        self.assertNotIn("8081", titles)

    def test_su_binary_is_low(self):
        result = self.scan({"[ -e '/system/xbin/su' ] && echo YES": "YES\n"})
        self.assertEqual([f.severity for f in result.findings], [Severity.LOW])
        self.assertEqual(result.verdict, Verdict.NO_IOC_MATCH)


class DnsTests(unittest.TestCase):
    def test_private_dns_on_c2_domain(self):
        adb = FakeAdb({"settings get global private_dns_specifier": "dns.Evil.Example.\n"})
        result = run_scan(adb, [TEST_IOC], only=["network"])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, Severity.HIGH)
        plan = build_plan(result)
        self.assertEqual(len(plan), 1)
        self.assertTrue(plan[0].manual_only)
        self.assertIn("private_dns_specifier", plan[0].description)

    def test_ordinary_dns_is_not_flagged(self):
        adb = FakeAdb({"settings get global private_dns_specifier": "dns.google\n", "getprop net.dns1": "8.8.8.8\n"})
        self.assertEqual(run_scan(adb, [TEST_IOC], only=["network"]).findings, [])

    def test_dns_server_is_c2_ip(self):
        adb = FakeAdb({"getprop net.dns1": "1.2.3.4\n"})
        self.assertEqual(len(run_scan(adb, [TEST_IOC], only=["network"]).findings), 1)


class CrossCheckTests(unittest.TestCase):
    def test_hidden_process(self):
        adb = FakeAdb({
            "ls /proc": "1\n2\n3\n4\n812\nself\nnet\n",
            PS: "  PID NAME\n    1 init\n    2 kthreadd\n    3 a\n    4 b\n",
            "cat /proc/812/comm 2>/dev/null": "vo1d\n",
        }, root=True)
        result = run_scan(adb, [TEST_IOC], only=["crosscheck"])
        self.assertEqual([f.title for f in result.findings], ["Process hidden from ps: vo1d (pid 812)"])
        self.assertEqual(build_plan(result), [])

    def test_unreadable_ps_is_an_error_not_a_flood(self):
        adb = FakeAdb({"ls /proc": "1\n2\n3\n4\n5\n", PS: "  PID NAME\n    1 init\n"}, root=True)
        result = run_scan(adb, [TEST_IOC], only=["crosscheck"])
        self.assertEqual(result.findings, [])
        self.assertTrue(result.errors and "cross-check skipped" in result.errors[0])

    def test_hidden_package(self):
        adb = FakeAdb({
            PACKAGES_XML_CMD: '<packages><package name="com.ok" codePath="/x"/>'
                              '<package name="com.ghost" codePath="/y"/>'
                              '<shared-user name="android.uid.system"/></packages>',
            "pm list packages -u": "package:com.ok\n",
        }, root=True)
        result = run_scan(adb, [TEST_IOC], only=["crosscheck"])
        self.assertEqual([f.target for f in result.findings], ["com.ghost"])

    def test_packages_xml_needs_root(self):
        adb = FakeAdb({PACKAGES_XML_CMD: '<package name="com.ghost"/>', "pm list packages -u": "package:a\n"})
        run_scan(adb, [TEST_IOC], only=["crosscheck"])
        self.assertNotIn(PACKAGES_XML_CMD, adb.commands)


def report(verdict, *findings, model="T95 Max"):
    return {"verdict": verdict, "device": {"ro.product.model": model, "ro.build.fingerprint": "fp"},
            "findings": list(findings)}


def finding(title, severity="CRITICAL", **kw):
    base = {"scanner": "files", "target_type": "file", "target": title, "title": title, "severity": severity,
            "evidence": {}}
    return {**base, **kw}


class CompareTests(unittest.TestCase):
    def test_gone_remaining_new(self):
        before = report("infected_firmware",
                        finding("/system/xbin/vo1d"),
                        finding("vo1d pid 812", scanner="processes", target_type="process", target="812",
                                evidence={"name": "/system/xbin/vo1d"}))
        after = report("infected_firmware",
                       finding("vo1d pid 455", scanner="processes", target_type="process", target="455",
                               evidence={"name": "/system/xbin/vo1d"}),  # new pid after reboot, same process
                       finding("model", severity="MEDIUM", scanner="device", target_type="device", target="T95"))
        c = compare(before, after)
        self.assertEqual([f["title"] for f in c.gone], ["/system/xbin/vo1d"])
        self.assertEqual([f["title"] for f in c.remaining], ["vo1d pid 455"])
        self.assertEqual([f["title"] for f in c.new], ["model"])
        self.assertEqual(len(c.high_left), 1)
        self.assertIn("came back", format_comparison(c))

    def test_all_gone_is_not_called_clean(self):
        c = compare(report("infected_removable", finding("/data/x")), report("no_ioc_match"))
        text = format_comparison(c)
        self.assertEqual(c.high_left, [])
        self.assertIn("not proof the box is clean", text)

    def test_different_device_warns(self):
        c = compare(report("no_ioc_match"), report("no_ioc_match", model="X96"))
        self.assertIn("different models", format_comparison(c))

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b, bad = Path(tmp, "a.json"), Path(tmp, "b.json"), Path(tmp, "bad.json")
            a.write_text(json.dumps(report("infected_removable", finding("/data/x"))), encoding="utf-8")
            b.write_text(json.dumps(report("no_ioc_match")), encoding="utf-8")
            bad.write_text("[1, 2]", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["compare", str(a), str(b)]), 0)
                self.assertEqual(cli.main(["compare", str(a), str(a)]), 1)
                self.assertEqual(cli.main(["compare", str(a), str(bad)]), 2)


class RedactTests(unittest.TestCase):
    def test_lan_ips_and_proxy_masked_c2_kept(self):
        adb = FakeAdb({
            **INFECTED,
            "settings get global http_proxy": "192.168.1.9:3128\n",
            "cat /proc/net/tcp 2>/dev/null": INFECTED["cat /proc/net/tcp 2>/dev/null"],
        }, root=True)
        result = run_scan(adb, [TEST_IOC])
        text = json.dumps(redacted(result).to_dict())
        self.assertNotIn("192.168.1.9", text)
        self.assertIn("1.2.3.4", text)      # C2 IP is a public IOC
        self.assertIn("<redacted>", text)
        self.assertIn("192.168.1.9", json.dumps(result.to_dict()))  # original untouched


class ScanAllTests(unittest.TestCase):
    def test_scan_all_writes_one_report_per_authorized_device(self):
        made = []

        def fake_adb(serial=None, adb_path="adb"):
            made.append(serial)
            return FakeAdb(INFECTED, root=True)

        original = cli.Adb
        cli.Adb = fake_adb
        try:
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
                iocs, out = Path(tmp, "iocs"), Path(tmp, "out")
                iocs.mkdir()
                (iocs / "test.json").write_text(json.dumps({"family": "TestFam", "packages": ["com.evil.sdk"]}),
                                                encoding="utf-8")
                code = cli.main(["--ioc-dir", str(iocs), "scan", "--all", "--out-dir", str(out), "--only", "packages"])
                files = sorted(p.name for p in out.iterdir())
        finally:
            cli.Adb = original
        self.assertEqual(code, 1)  # infected
        self.assertEqual(files, ["scan-box.html", "scan-box.json"])  # "other" is unauthorized
        self.assertIn("box", made)

    def test_report_names_are_safe(self):
        self.assertEqual(cli._report_name("192.168.1.5:5555"), "scan-192.168.1.5_5555")
        self.assertEqual(cli._report_name("../../x"), "scan-x")
        self.assertEqual(cli._report_name("..."), "scan-device")

    def test_all_rejects_single_device_flags(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["-s", "box", "scan", "--all"]), 2)


class I18nTests(unittest.TestCase):
    UI_FILES = ["src/tvbox_scanner/ui/app.py", "src/tvbox_scanner/ui/widgets.py"]

    def test_every_ui_string_has_english(self):
        root = Path(__file__).resolve().parents[1]
        missing = []
        for rel in self.UI_FILES:
            source = (root / rel).read_text(encoding="utf-8")
            # t("a" "b") spanning lines: join adjacent literals first
            for call in re.findall(r'\bt\(((?:\s*"(?:[^"\\]|\\.)*")+)\s*\)', source):
                text = "".join(eval(lit) for lit in re.findall(r'"(?:[^"\\]|\\.)*"', call))  # noqa: S307
                if text not in i18n.EN:
                    missing.append(text)
        self.assertEqual(missing, [])

    def test_english_ui(self):
        try:
            import textual  # noqa: F401
        except ImportError:
            self.skipTest("textual not installed")
        import tvbox_scanner.ui.app as app
        import tvbox_scanner.ui.widgets as widgets
        try:
            i18n.set_language("en")
            importlib.reload(widgets)
            importlib.reload(app)
            self.assertEqual(widgets.VERDICT_UI[Verdict.NO_IOC_MATCH][1], "NO IOC MATCH")
            self.assertIn(("r", "remove", "Remove botnet"), app.ScanScreen.BINDINGS)
        finally:
            i18n.set_language("ms")
            importlib.reload(widgets)
            importlib.reload(app)

    def test_unknown_language_falls_back(self):
        i18n.set_language("xx")
        self.assertEqual(i18n.language(), "ms")


class ExecutorFailureTests(unittest.TestCase):
    def action(self, **kw):
        base = dict(description="rm x", commands=["rm -rf '/data/x'"], risk=Risk.SAFE, backup_paths=["/data/x"])
        return Action(**{**base, **kw})

    def test_failed_backup_stops_before_delete(self):
        class PullFails(FakeAdb):
            def pull(self, remote, local):
                raise OSError("adb: error: remote object '/data/x' does not exist")

        adb = PullFails({})
        with tempfile.TemporaryDirectory() as tmp:
            results = execute_plan(adb, [self.action(), self.action(description="second")], apply=True,
                                   backup_root=Path(tmp))
            log = json.loads(next(Path(tmp).glob("*/actions.json")).read_text(encoding="utf-8"))
        self.assertEqual([r.status for r in results], ["failed"])
        self.assertIn("does not exist", results[0].message)
        self.assertNotIn("rm -rf '/data/x'", adb.commands)  # never deleted without a backup
        self.assertEqual(log[0]["status"], "failed")

    def test_failed_push_stops_plan(self):
        class PushFails(FakeAdb):
            def push(self, local, remote):
                raise OSError("push failed")

        adb = PushFails({})
        with tempfile.TemporaryDirectory() as tmp:
            results = execute_plan(adb, [self.action(backup_paths=[], uploads=[("a", "/data/local/tmp/a")]),
                                         self.action(backup_paths=[])], apply=True, backup_root=Path(tmp))
        self.assertEqual([r.status for r in results], ["failed"])
        self.assertEqual(adb.commands, [])


if __name__ == "__main__":
    unittest.main()
