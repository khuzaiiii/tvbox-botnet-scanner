import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import textual  # noqa: F401
except ImportError:  # UI is an optional extra
    textual = None

from fake_adb import FakeAdb  # noqa: E402
from test_scan import INFECTED, TEST_IOC  # noqa: E402


@unittest.skipIf(textual is None, "textual not installed")
class UiTests(unittest.IsolatedAsyncioTestCase):
    def make_app(self, responses, root=True, serial="box"):
        from tvbox_scanner.ui.app import TvBoxApp
        self.adb = FakeAdb(responses, root=root)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        return TvBoxApp(lambda s: self.adb, [TEST_IOC], serial=serial,
                        backup_root=Path(self.tmp.name) / "backups", report_dir=Path(self.tmp.name) / "reports")

    async def settle(self, pilot):
        await pilot.app.workers.wait_for_complete()
        await pilot.pause()

    async def test_scan_then_remove_flow(self):
        from textual.widgets import Button, DataTable, RichLog, SelectionList, Static, Switch
        from tvbox_scanner.ui.app import ConfirmModal, RemoveScreen, ScanScreen

        app = self.make_app(INFECTED)
        async with app.run_test(size=(140, 45)) as pilot:
            await self.settle(pilot)
            scan = app.screen
            self.assertIsInstance(scan, ScanScreen)
            self.assertEqual(scan.query_one("#findings", DataTable).row_count, len(scan.result.findings))
            self.assertIn("DIJANGKITI", str(scan.query_one("#verdict", Static).render()))
            self.assertFalse(scan.query_one("#remove", Button).disabled)

            await pilot.press("w")  # save report
            await pilot.pause()
            self.assertTrue(list((Path(self.tmp.name) / "reports").glob("scan-*.html")))

            await pilot.press("r")
            await pilot.pause()
            remove = app.screen
            self.assertIsInstance(remove, RemoveScreen)
            sl = remove.query_one("#plan", SelectionList)
            dangerous = [i for i, a in enumerate(remove.plan) if a.risk.name == "DANGEROUS"]
            self.assertTrue(dangerous)
            self.assertTrue(all(i not in sl.selected for i in dangerous))  # /system off by default

            remove.query_one("#allow-system", Switch).value = True
            await pilot.pause()
            self.assertTrue(all(i in sl.selected for i in dangerous))

            await pilot.click("#apply")
            await pilot.pause()
            self.assertIsInstance(app.screen, ConfirmModal)
            await pilot.click("#yes")
            await self.settle(pilot)

            self.assertTrue(any(c.startswith("kill -9") for c in self.adb.commands))
            self.assertIn("rm -rf '/system/xbin/vo1d'", self.adb.commands)
            log_text = "\n".join(str(line.text) for line in remove.query_one("#log", RichLog).lines)
            self.assertIn("Selesai", log_text)
            self.assertFalse(remove.query_one("#rescan", Button).disabled)

            await pilot.click("#rescan")
            await self.settle(pilot)
            self.assertIs(app.screen, scan)

    async def test_cancel_confirm_runs_nothing(self):
        app = self.make_app(INFECTED)
        async with app.run_test(size=(140, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("r")
            await pilot.pause()
            before = list(self.adb.commands)
            await pilot.click("#apply")
            await pilot.pause()
            await pilot.click("#no")
            await self.settle(pilot)
            self.assertEqual(self.adb.commands, before)

    async def test_device_markup_is_not_interpreted(self):
        # A malicious process name must render literally, not as Textual markup/actions.
        from textual.widgets import DataTable
        responses = dict(INFECTED)
        evil = "[@click=app.quit]vo1d"
        responses["ps -A -o PID,NAME 2>/dev/null"] = f"  PID NAME\n  812 {evil}\n"
        ioc = type(TEST_IOC).from_dict({"family": "X", "process_names": [evil]})
        from tvbox_scanner.ui.app import TvBoxApp
        self.adb = FakeAdb(responses, root=True)
        app = TvBoxApp(lambda s: self.adb, [ioc], serial="box")
        async with app.run_test(size=(140, 45)) as pilot:
            await self.settle(pilot)
            table = app.screen.query_one("#findings", DataTable)
            titles = [table.get_row_at(i)[2].plain for i in range(table.row_count)]
            self.assertTrue(any("[@click=app.quit]vo1d" in t for t in titles), titles)
            self.assertTrue(app.is_running)

    async def test_device_picker(self):
        from tvbox_scanner.ui.app import DeviceScreen, ScanScreen
        app = self.make_app(INFECTED, serial=None)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            self.assertIsInstance(app.screen, DeviceScreen)
            from textual.widgets import ListView
            lv = app.screen.query_one("#devices", ListView)
            lv.index = 1  # 'other' is unauthorized -> stays on picker
            await pilot.press("enter")
            await pilot.pause()
            self.assertIsInstance(app.screen, DeviceScreen)
            lv.index = 0
            await pilot.press("enter")
            await self.settle(pilot)
            self.assertIsInstance(app.screen, ScanScreen)


if __name__ == "__main__":
    unittest.main()
