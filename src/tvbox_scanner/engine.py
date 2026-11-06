from __future__ import annotations

from typing import Callable

from tvbox_scanner.models import Finding, ScanResult
from tvbox_scanner.scanners import ALL_SCANNERS, ScanOptions
from tvbox_scanner.scanners.device import read_props

# on_progress(scanner_name, status, payload)
#   status "running": payload None
#   status "done":    payload list[Finding] from that scanner
#   status "error":   payload error message
ProgressCallback = Callable[[str, str, "list[Finding] | str | None"], None]


def selected_scanners(only: list[str] | None = None) -> list[str]:
    return [name for name in ALL_SCANNERS if not only or name in only]


def run_scan(
    adb,
    iocs,
    options: ScanOptions | None = None,
    only: list[str] | None = None,
    on_progress: ProgressCallback | None = None,
) -> ScanResult:
    options = options or ScanOptions()
    notify = on_progress or (lambda *_: None)
    findings, errors = [], []
    for name in selected_scanners(only):
        notify(name, "running", None)
        try:
            found = ALL_SCANNERS[name](adb, iocs, options)
        except Exception as exc:  # one broken scanner must not hide the others' results
            errors.append(f"{name}: {exc}")
            notify(name, "error", str(exc))
            continue
        findings.extend(found)
        notify(name, "done", found)
    return ScanResult(
        device=read_props(adb),
        findings=findings,
        root=adb.has_root(),
        ioc_families=[i.family for i in iocs],
        errors=errors,
    )
