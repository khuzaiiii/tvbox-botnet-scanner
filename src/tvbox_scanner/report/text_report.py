from __future__ import annotations

from tvbox_scanner.models import ScanResult, Verdict

VERDICT_TEXT = {
    Verdict.NO_IOC_MATCH: "No known IOC matched. This does not prove the box is clean.",
    Verdict.SUSPICIOUS: "Suspicious indicators found. Review the findings below.",
    Verdict.INFECTED_REMOVABLE: "Infected. Malware lives in /data and can likely be removed.",
    Verdict.INFECTED_FIRMWARE: "Infected at firmware level. Removal needs root and may not survive a reboot; "
                               "reflashing clean firmware or replacing the box is the reliable fix.",
}


def format_text(result: ScanResult) -> str:
    d = result.device
    lines = [
        f"Device : {d.get('ro.product.manufacturer')} {d.get('ro.product.model')} "
        f"(Android {d.get('ro.build.version.release')}, {d.get('ro.board.platform')})",
        f"Root   : {'yes' if result.root else 'no (firmware paths under /data/system may be invisible)'}",
        f"IOCs   : {', '.join(result.ioc_families)}",
        f"Verdict: {result.verdict.value.upper()} - {VERDICT_TEXT[result.verdict]}",
        "",
    ]
    for f in sorted(result.findings, key=lambda f: -f.severity):
        lines.append(f"[{f.severity.name:8}] {f.title}")
        if f.detail:
            lines.append(f"           {f.detail}")
    if result.errors:
        lines.append("")
        lines += [f"scanner error: {e}" for e in result.errors]
    return "\n".join(lines)
