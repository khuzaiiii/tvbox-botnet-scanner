"""Textual app: pick device -> live scan -> choose and run remediation."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Callable

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    ProgressBar,
    RichLog,
    SelectionList,
    Static,
    Switch,
)
from textual.widgets.selection_list import Selection

from tvbox_scanner.engine import run_scan, selected_scanners
from tvbox_scanner.models import Finding, ScanResult, Verdict
from tvbox_scanner.remediation import Action, Risk, build_plan, execute_plan
from tvbox_scanner.remediation.executor import ActionResult
from tvbox_scanner.report import write_html, write_json
from tvbox_scanner.scanners import ScanOptions
from tvbox_scanner.ui.widgets import VERDICT_UI, plain, risk_badge, severity_cell

SCANNER_LABELS = {
    "device": "Maklumat device",
    "packages": "Aplikasi terpasang",
    "files": "Fail sistem (IOC)",
    "processes": "Proses berjalan",
    "network": "Sambungan rangkaian",
}
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
STATUS_ICON = {"pending": ("○", "dim"), "done": ("✔", "bold green"), "error": ("✖", "bold red")}
RESULT_BADGE = {
    "done": (" ✔ SIAP ", "bold black on green"),
    "failed": (" ✖ GAGAL ", "bold white on red"),
    "dry-run": (" DRY RUN ", "bold black on cyan"),
    "skipped": (" LANGKAU ", "dim reverse"),
}

AdbFactory = Callable[[str | None], object]


def _display_path(path: Path) -> str:
    """Relative to the current folder when it's under it (shorter, and no user name on screen)."""
    full = path.resolve()
    try:
        return str(full.relative_to(Path.cwd().resolve())) + os.sep
    except ValueError:
        return str(full)


# --------------------------------------------------------------------------- device picker

class DeviceScreen(Screen):
    BINDINGS = [("f5", "refresh", "Muat semula")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="device-box"):
            yield Static("Pilih TV box", classes="title")
            yield Static(
                "Sambung guna kabel USB, atau aktifkan ADB rangkaian pada box dan masukkan IP di bawah.",
                classes="hint",
            )
            yield ListView(id="devices")
            yield Static("", id="device-msg", classes="hint")
            with Horizontal(classes="row"):
                yield Input(placeholder="192.168.1.50:5555", id="host")
                yield Button("Sambung", id="connect", variant="primary")
                yield Button("Muat semula", id="refresh")
        yield Footer()

    def on_mount(self) -> None:
        self.action_refresh()

    def action_refresh(self) -> None:
        lv = self.query_one("#devices", ListView)
        lv.clear()
        try:
            devices = self.app.adb_factory(None).devices()
        except Exception as exc:
            self._msg(str(exc), error=True)
            return
        if not devices:
            self._msg("Tiada device. Semak kabel / IP, dan benarkan USB debugging pada TV.")
        for d in devices:
            item = ListItem(Label(Text.assemble(
                ("● " if d.state == "device" else "○ ", "green" if d.state == "device" else "yellow"),
                plain(d.serial, "bold"), "  ", plain(d.state, "dim"),
            )))
            item.serial = d.serial  # type: ignore[attr-defined]
            item.state = d.state  # type: ignore[attr-defined]
            lv.append(item)
        if devices:
            self._msg("Pilih device dan tekan Enter.")
            lv.focus()

    def _msg(self, text: str, error: bool = False) -> None:
        self.query_one("#device-msg", Static).update(plain(text, "bold red" if error else ""))

    @on(Button.Pressed, "#refresh")
    def _refresh(self) -> None:
        self.action_refresh()

    @on(Button.Pressed, "#connect")
    @on(Input.Submitted, "#host")
    def _connect(self) -> None:
        host = self.query_one("#host", Input).value.strip()
        if host:
            self._msg(f"Menyambung ke {host}...")
            self._do_connect(host)

    @work(thread=True, exclusive=True)
    def _do_connect(self, host: str) -> None:
        try:
            out = self.app.adb_factory(None).connect(host)
            self.app.call_from_thread(self._msg, out)
            self.app.call_from_thread(self.action_refresh)
        except Exception as exc:
            self.app.call_from_thread(self._msg, str(exc), True)

    @on(ListView.Selected, "#devices")
    def _picked(self, event: ListView.Selected) -> None:
        if getattr(event.item, "state", "") != "device":
            self._msg("Device belum dibenarkan. Terima prompt 'Allow USB debugging' pada skrin TV.", error=True)
            return
        self.app.open_device(event.item.serial)  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- scan

class ScanScreen(Screen):
    BINDINGS = [
        ("s", "scan(False)", "Scan"),
        ("D", "scan(True)", "Deep scan"),
        ("r", "remove", "Buang botnet"),
        ("w", "save", "Simpan report"),
        ("escape", "back", "Tukar device"),
    ]

    def __init__(self, adb, serial: str) -> None:
        super().__init__()
        self.adb = adb
        self.serial = serial
        self.result: ScanResult | None = None
        self.findings: list[Finding] = []
        self.step_state: dict[str, str] = {}
        self.frame = 0

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="device-bar")
        with Horizontal(id="scan-body"):
            with Vertical(id="steps"):
                yield Static("Langkah scan", classes="title")
                for name in SCANNER_LABELS:
                    yield Static(id=f"step-{name}", classes="step")
                yield ProgressBar(id="scan-progress", show_eta=False)
            with Vertical(id="findings-pane"):
                table = DataTable(id="findings", cursor_type="row", zebra_stripes=True)
                yield table
                yield VerticalScroll(Static(id="detail"), id="detail-box")
        yield Static(id="verdict")
        with Horizontal(classes="row buttons"):
            yield Button("Scan semula", id="scan", variant="primary")
            yield Button("Deep scan", id="deep")
            yield Button("Buang botnet ▶", id="remove", variant="error", disabled=True)
            yield Button("Simpan report", id="save", disabled=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#findings", DataTable).add_columns("Tahap", "Famili", "Penemuan")
        self.query_one("#device-bar", Static).update(plain(f"Device: {self.serial}", "bold"))
        self.set_interval(0.1, self._tick)
        self.action_scan(False)

    # --- scanning -------------------------------------------------------------------------

    def action_scan(self, deep: bool) -> None:
        if any(s == "running" for s in self.step_state.values()):
            return
        self.result = None
        self.findings = []
        self.query_one("#findings", DataTable).clear()
        self.query_one("#detail", Static).update("")
        verdict = self.query_one("#verdict", Static)
        verdict.set_classes("")
        verdict.update(Text("Sedang scan" + (" (deep: hash setiap APK, mungkin lambat)" if deep else "") + "...",
                            style="italic"))
        for b in ("#remove", "#save", "#scan", "#deep"):
            self.query_one(b, Button).disabled = True
        names = selected_scanners()
        self.step_state = {n: "pending" for n in names}
        self._render_steps()
        self.query_one("#scan-progress", ProgressBar).update(total=len(names), progress=0)
        self._scan_worker(deep)

    @work(thread=True, exclusive=True, group="scan")
    def _scan_worker(self, deep: bool) -> None:
        def progress(name, status, payload):
            self.app.call_from_thread(self._on_progress, name, status, payload)
        try:
            result = run_scan(self.adb, self.app.iocs, ScanOptions(deep=deep), on_progress=progress)
        except Exception as exc:
            self.app.call_from_thread(self._scan_failed, str(exc))
            return
        self.app.call_from_thread(self._scan_finished, result)

    def _on_progress(self, name: str, status: str, payload) -> None:
        self.step_state[name] = status
        if status in ("done", "error"):
            self.query_one("#scan-progress", ProgressBar).advance(1)
        if status == "done":
            for f in payload:
                self._add_finding(f)
        if status == "error":
            self.notify(f"{SCANNER_LABELS.get(name, name)}: {payload}", title="Ralat scanner",
                        severity="error", markup=False)
        self._render_steps()

    def _add_finding(self, f: Finding) -> None:
        self.findings.append(f)
        self.query_one("#findings", DataTable).add_row(
            severity_cell(f.severity), plain(f.family or "-"), plain(f.title), key=str(len(self.findings) - 1)
        )

    def _scan_finished(self, result: ScanResult) -> None:
        self.result = result
        d = result.device
        self.query_one("#device-bar", Static).update(Text.assemble(
            ("Device: ", "dim"), plain(f"{d.get('ro.product.manufacturer')} {d.get('ro.product.model')}", "bold"),
            ("   Android ", "dim"), plain(d.get("ro.build.version.release")),
            ("   Chip ", "dim"), plain(d.get("ro.board.platform")),
            ("   Root ", "dim"), ("YA", "bold green") if result.root else ("TIDAK", "bold yellow"),
            ("   Serial ", "dim"), plain(self.serial),
        ))
        css, title, text = VERDICT_UI[result.verdict]
        verdict = self.query_one("#verdict", Static)
        verdict.set_classes(css)
        verdict.update(Text.assemble((f" {title} ", "bold reverse"), "  ", text,
                                     f"\n{len(result.findings)} penemuan dari {len(result.ioc_families)} famili IOC."))
        has_plan = bool(build_plan(result))
        self.query_one("#remove", Button).disabled = not has_plan
        for b in ("#save", "#scan", "#deep"):
            self.query_one(b, Button).disabled = False
        if not self.findings:
            self.query_one("#detail", Static).update(Text("Tiada penemuan.", style="dim"))
        else:
            # Rows arrive in scanner order while scanning; once done, worst first.
            table = self.query_one("#findings", DataTable)
            self.findings.sort(key=lambda f: -f.severity)
            table.clear()
            for i, f in enumerate(self.findings):
                table.add_row(severity_cell(f.severity), plain(f.family or "-"), plain(f.title), key=str(i))
            table.move_cursor(row=0)
            table.focus()

    def _scan_failed(self, message: str) -> None:
        verdict = self.query_one("#verdict", Static)
        verdict.set_classes("verdict-infected")
        verdict.update(Text.assemble((" RALAT ", "bold reverse"), "  ", plain(message)))
        self.step_state = {n: ("error" if s == "running" else s) for n, s in self.step_state.items()}
        self._render_steps()
        for b in ("#scan", "#deep"):
            self.query_one(b, Button).disabled = False

    def _tick(self) -> None:
        if any(s == "running" for s in self.step_state.values()):
            self.frame = (self.frame + 1) % len(SPINNER)
            self._render_steps()

    def _render_steps(self) -> None:
        for name, label in SCANNER_LABELS.items():
            state = self.step_state.get(name, "pending")
            if state == "running":
                icon, style = SPINNER[self.frame], "bold cyan"
            else:
                icon, style = STATUS_ICON[state]
            count = sum(1 for f in self.findings if f.scanner == name)
            suffix = Text(f"  {count}", style="bold red") if count else Text("")
            self.query_one(f"#step-{name}", Static).update(
                Text.assemble((f" {icon} ", style), (label, "bold" if state == "running" else ""), suffix)
            )

    @on(DataTable.RowHighlighted, "#findings")
    def _show_detail(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        f = self.findings[int(event.row_key.value)]
        parts = [plain(f.title, "bold"), "\n"]
        if f.detail:
            parts += [plain(f.detail, "italic"), "\n"]
        for k, v in f.evidence.items():
            parts += [(f"{k}: ", "dim"), plain(v), "\n"]
        self.query_one("#detail", Static).update(Text.assemble(*parts))

    # --- actions --------------------------------------------------------------------------

    @on(Button.Pressed, "#scan")
    def _btn_scan(self) -> None:
        self.action_scan(False)

    @on(Button.Pressed, "#deep")
    def _btn_deep(self) -> None:
        self.action_scan(True)

    @on(Button.Pressed, "#remove")
    def action_remove(self) -> None:
        if self.result is None or self.query_one("#remove", Button).disabled:
            return
        self.app.push_screen(RemoveScreen(self.adb, self.result), self._after_remove)

    def _after_remove(self, rescan: bool | None) -> None:
        if rescan:
            self.action_scan(False)

    @on(Button.Pressed, "#save")
    def action_save(self) -> None:
        if self.result is None:
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        base = self.app.report_dir / f"scan-{stamp}"
        write_json(self.result, base.with_suffix(".json"))
        write_html(self.result, base.with_suffix(".html"))
        self.notify(f"{base}.html\n{base}.json", title="Report disimpan", markup=False)

    def action_back(self) -> None:
        if not self.app.fixed_serial:
            self.app.pop_screen()


# --------------------------------------------------------------------------- remove

class ConfirmModal(ModalScreen[bool]):
    BINDINGS = [("escape", "dismiss(False)", "Batal")]

    def __init__(self, body: Text) -> None:
        super().__init__()
        self.body = body

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-box"):
            yield Static("Sahkan tindakan", classes="title")
            yield Static(self.body)
            with Horizontal(classes="row buttons"):
                yield Button("Batal", id="no")
                yield Button("Ya, laksana", id="yes", variant="error")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    @on(Button.Pressed, "#yes")
    def _yes(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#no")
    def _no(self) -> None:
        self.dismiss(False)


class RemoveScreen(Screen[bool]):
    BINDINGS = [("escape", "back", "Kembali")]

    def __init__(self, adb, result: ScanResult) -> None:
        super().__init__()
        self.adb = adb
        self.result = result
        self.plan: list[Action] = build_plan(result)
        self.has_root = result.root
        self.running = False
        self.finished = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="remove-body"):
            with Vertical(id="plan-pane"):
                yield Static("Pelan pembuangan", classes="title")
                if self.result.verdict == Verdict.INFECTED_FIRMWARE:
                    yield Static(
                        "Malware dalam firmware. Langkah /SYSTEM boleh menyebabkan bootloop; "
                        "setiap fail di-backup ke PC dulu.", classes="warn")
                with Horizontal(classes="row switch-row"):
                    yield Switch(id="allow-system")
                    yield Label("Benarkan ubah /system (risiko bootloop)")
                yield SelectionList[int](*self._selections(False), id="plan")
                yield VerticalScroll(Static(id="action-detail"), id="action-detail-box")
            with Vertical(id="log-pane"):
                yield Static("Log", classes="title")
                yield ProgressBar(id="remove-progress", show_eta=False)
                yield RichLog(id="log", markup=False, wrap=True, min_width=20)
        with Horizontal(classes="row buttons"):
            yield Button("Kembali", id="back")
            yield Button("Dry run", id="dry")
            yield Button("Laksana", id="apply", variant="error")
            yield Button("Reboot box", id="reboot", disabled=True)
            yield Button("Scan semula", id="rescan", variant="primary", disabled=True)
        yield Footer()

    def _blocked_reason(self, action: Action, allow_system: bool) -> str | None:
        if action.manual_only:
            return "langkah manual"
        if action.requires_root and not self.has_root:
            return "perlu root"
        if action.risk == Risk.DANGEROUS and not allow_system:
            return "aktifkan suis /system"
        return None

    def _selections(self, allow_system: bool) -> list[Selection]:
        items = []
        for i, a in enumerate(self.plan):
            reason = self._blocked_reason(a, allow_system)
            prompt = Text.assemble(risk_badge(a.risk), " ", plain(a.description))
            if reason:
                prompt.append(f"  ({reason})", style="dim italic")
            items.append(Selection(prompt, i, initial_state=reason is None, id=f"a{i}", disabled=reason is not None))
        return items

    def on_mount(self) -> None:
        log = self.query_one("#log", RichLog)
        log.write(Text(f"{len(self.plan)} langkah dirancang. Pilih langkah, kemudian 'Dry run' atau 'Laksana'.",
                       style="dim"))
        if not self.has_root:
            log.write(Text("Tiada root: hanya app pengguna boleh dibuang; app sistem hanya di-disable untuk user 0.",
                           style="yellow"))
        self.query_one("#plan", SelectionList).focus()

    @on(Switch.Changed, "#allow-system")
    def _toggle_system(self, event: Switch.Changed) -> None:
        sl = self.query_one("#plan", SelectionList)
        for i, a in enumerate(self.plan):
            if a.risk != Risk.DANGEROUS or a.manual_only or (a.requires_root and not self.has_root):
                continue
            if event.value:
                sl.enable_option(f"a{i}")
                sl.select(i)
            else:
                sl.deselect(i)
                sl.disable_option(f"a{i}")

    @on(SelectionList.SelectionHighlighted, "#plan")
    def _show_action(self, event: SelectionList.SelectionHighlighted) -> None:
        a = self.plan[event.selection.value]
        parts: list = [plain(a.description, "bold"), "\n"]
        for c in a.commands:
            parts += [("$ ", "dim"), plain(c, "cyan"), "\n"]
        for b in a.backup_paths:
            parts += [("backup: ", "dim"), plain(b), "\n"]
        if a.requires_root:
            parts += [("perlu root", "yellow"), "\n"]
        self.query_one("#action-detail", Static).update(Text.assemble(*parts))

    def _chosen(self) -> list[Action]:
        selected = set(self.query_one("#plan", SelectionList).selected)
        return [a for i, a in enumerate(self.plan) if i in selected]

    @on(Button.Pressed, "#dry")
    def _dry(self) -> None:
        self._start(apply=False)

    @on(Button.Pressed, "#apply")
    def _apply(self) -> None:
        chosen = self._chosen()
        if not chosen:
            self.notify("Tiada langkah dipilih.", severity="warning")
            return
        dangerous = sum(1 for a in chosen if a.risk == Risk.DANGEROUS)
        body = Text.assemble(
            (f"{len(chosen)} langkah", "bold"), " akan dijalankan pada ", plain(self.app.serial_label, "bold"), ".\n",
            ("Fail di-backup ke ", ""), plain(_display_path(self.app.backup_root), "cyan"), " sebelum dipadam.\n",
        )
        if dangerous:
            body.append(f"\n{dangerous} langkah mengubah /system dan boleh menyebabkan bootloop.\n", style="bold red")
        self.app.push_screen(ConfirmModal(body), lambda ok: ok and self._start(apply=True))

    def _start(self, apply: bool) -> None:
        if self.running:
            return
        chosen = self._chosen()
        if not chosen:
            self.notify("Tiada langkah dipilih.", severity="warning")
            return
        self.running = True
        for b in ("#dry", "#apply", "#back", "#rescan", "#reboot"):
            self.query_one(b, Button).disabled = True
        self.query_one("#plan", SelectionList).disabled = True
        self.query_one("#allow-system", Switch).disabled = True
        self.query_one("#remove-progress", ProgressBar).update(total=len(chosen), progress=0)
        log = self.query_one("#log", RichLog)
        log.write(Text(f"\n── {'LAKSANA' if apply else 'DRY RUN'} ({len(chosen)} langkah) ──", style="bold"))
        self._run_worker(chosen, apply, self.query_one("#allow-system", Switch).value)

    @work(thread=True, exclusive=True, group="remove")
    def _run_worker(self, chosen: list[Action], apply: bool, allow_system: bool) -> None:
        try:
            results = execute_plan(
                self.adb, chosen,
                apply=apply,
                allow_dangerous=allow_system,
                backup_root=self.app.backup_root,
                on_start=lambda i, a: self.app.call_from_thread(self._on_start, a),
                on_result=lambda i, r: self.app.call_from_thread(self._on_result, r),
            )
        except Exception as exc:
            self.app.call_from_thread(self._log_error, str(exc))
            results = []
        self.app.call_from_thread(self._finished, results, apply)

    def _on_start(self, action: Action) -> None:
        # Slow steps (backup pull, rm on /system) show up immediately; the result line follows.
        self.query_one("#log", RichLog).write(Text.assemble(("  ▸ ", "bold cyan"), plain(action.description)))
        self.started = action

    def _on_result(self, r: ActionResult) -> None:
        self.query_one("#remove-progress", ProgressBar).advance(1)
        log = self.query_one("#log", RichLog)
        label, style = RESULT_BADGE.get(r.status, (r.status, ""))
        if getattr(self, "started", None) is r.action:
            log.write(Text.assemble("    ", (label, style)))
        else:
            log.write(Text.assemble((label, style), " ", plain(r.action.description)))
        if r.status == "dry-run":
            for c in r.action.commands:
                log.write(Text.assemble(("    $ ", "dim"), plain(c, "cyan")))
        if r.message:
            log.write(Text.assemble("    ", plain(r.message, "red" if r.status == "failed" else "dim")))

    def _log_error(self, message: str) -> None:
        self.query_one("#log", RichLog).write(Text.assemble(("RALAT: ", "bold red"), plain(message)))

    def _finished(self, results: list[ActionResult], apply: bool) -> None:
        self.running = False
        log = self.query_one("#log", RichLog)
        done = sum(r.status == "done" for r in results)
        failed = sum(r.status == "failed" for r in results)
        if apply:
            self.finished = True
            log.write(Text(f"\nSelesai: {done} berjaya, {failed} gagal.",
                           style="bold red" if failed else "bold green"))
            log.write(Text("Reboot box, kemudian scan semula. Kalau fail muncul semula, malware ada dalam "
                           "partition yang tool ini tak boleh bersihkan: flash firmware bersih atau ganti box.",
                           style="yellow"))
            self.query_one("#reboot", Button).disabled = False
            self.query_one("#rescan", Button).disabled = False
        self.query_one("#back", Button).disabled = False
        self.query_one("#dry", Button).disabled = self.finished
        self.query_one("#apply", Button).disabled = self.finished
        if not self.finished:
            self.query_one("#plan", SelectionList).disabled = False
            self.query_one("#allow-system", Switch).disabled = False

    @on(Button.Pressed, "#reboot")
    def _reboot(self) -> None:
        try:
            self.adb.reboot()
        except Exception as exc:
            self._log_error(str(exc))
            return
        self.query_one("#log", RichLog).write(Text("Arahan reboot dihantar. Tunggu box hidup, kemudian 'Scan semula'.",
                                                   style="cyan"))

    @on(Button.Pressed, "#rescan")
    def _rescan(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#back")
    def action_back(self) -> None:
        if not self.running:
            self.dismiss(self.finished)


# --------------------------------------------------------------------------- app

class TvBoxApp(App):
    CSS_PATH = "app.tcss"
    TITLE = "TV Box Botnet Scanner"
    SUB_TITLE = "Vo1d · BADBOX · T95 Corejava"
    BINDINGS = [("q", "quit", "Keluar"), ("t", "toggle_theme", "Tema")]

    def __init__(self, adb_factory: AdbFactory, iocs, serial: str | None = None,
                 backup_root: Path = Path("backups"), report_dir: Path = Path("reports")) -> None:
        super().__init__()
        self.adb_factory = adb_factory
        self.iocs = iocs
        self.fixed_serial = serial
        self.serial_label = serial or ""
        self.backup_root = backup_root
        self.report_dir = report_dir

    def on_mount(self) -> None:
        self.theme = "tokyo-night"
        if self.fixed_serial:
            self.open_device(self.fixed_serial)
        else:
            self.push_screen(DeviceScreen())

    def open_device(self, serial: str) -> None:
        self.serial_label = serial
        self.push_screen(ScanScreen(self.adb_factory(serial), serial))

    def action_toggle_theme(self) -> None:
        self.theme = "textual-light" if self.theme == "tokyo-night" else "tokyo-night"


def run_ui(adb_factory: AdbFactory, iocs, serial: str | None, backup_root: Path) -> int:
    TvBoxApp(adb_factory, iocs, serial=serial, backup_root=backup_root).run()
    return 0
