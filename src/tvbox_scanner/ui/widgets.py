"""Shared rendering helpers.

Every string that came from the TV box (process names, package paths, props) is
attacker-controlled. Textual parses markup in plain `str` content, including
`[@click=...]` actions, so device strings are only ever rendered through
`plain()`, which builds a rich `Text` (no markup parsing, control codes stripped).
"""

from __future__ import annotations

from rich.text import Text

from tvbox_scanner.i18n import t
from tvbox_scanner.models import Severity, Verdict
from tvbox_scanner.remediation import Risk

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_LABEL = {
    Severity.CRITICAL: t(" KRITIKAL "),
    Severity.HIGH: t("TINGGI"),
    Severity.MEDIUM: t("SEDERHANA"),
    Severity.LOW: t("RENDAH"),
    Severity.INFO: "INFO",
}

RISK_BADGE = {
    Risk.SAFE: (t("SELAMAT"), "bold green"),
    Risk.MODERATE: (t("SEDERHANA"), "bold yellow"),
    Risk.DANGEROUS: ("/SYSTEM", "bold white on red"),
}

VERDICT_UI = {
    Verdict.NO_IOC_MATCH: ("verdict-clean", t("TIADA PADANAN IOC"),
                           t("Tiada tanda botnet yang dikenali. Ini bukan bukti box bersih: hanya IOC yang "
                             "disertakan disemak.")),
    Verdict.SUSPICIOUS: ("verdict-suspicious", t("MENCURIGAKAN"),
                         t("Ada petunjuk sederhana. Semak penemuan di atas.")),
    Verdict.INFECTED_REMOVABLE: ("verdict-infected", t("DIJANGKITI"),
                                 t("Malware berada dalam /data dan boleh dibuang. Tekan 'Buang botnet'.")),
    Verdict.INFECTED_FIRMWARE: ("verdict-infected", t("DIJANGKITI (FIRMWARE)"),
                                t("Malware tertanam dalam /system. Buang perlukan root dan mungkin kembali selepas "
                                  "reboot; flash firmware bersih atau ganti box adalah penyelesaian yang pasti.")),
}


def plain(value: object, style: str = "") -> Text:
    return Text(str(value), style=style)


def severity_cell(sev: Severity) -> Text:
    return Text(SEVERITY_LABEL[sev], style=SEVERITY_STYLE[sev])


def risk_badge(risk: Risk) -> Text:
    label, style = RISK_BADGE[risk]
    return Text(f" {label} ", style=style)
