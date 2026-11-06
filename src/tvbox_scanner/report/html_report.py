from __future__ import annotations

from html import escape
from pathlib import Path

from tvbox_scanner.models import ScanResult
from tvbox_scanner.report.text_report import VERDICT_TEXT

TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TV Box Scan Report</title>
<style>
body {{ font: 15px/1.5 system-ui, sans-serif; margin: 0 auto; padding: 16px; max-width: 960px;
       background: #fff; color: #1a1a1a; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #ddd; vertical-align: top; }}
.sev-CRITICAL, .sev-HIGH {{ color: #b00020; font-weight: 600; }}
.sev-MEDIUM {{ color: #8a5a00; }}
.verdict {{ padding: 12px; border-left: 4px solid #555; background: #f4f4f4; }}
code {{ word-break: break-all; }}
</style></head><body>
<h1>TV Box Scan Report</h1>
<p>{device}</p>
<p class="verdict"><strong>{verdict}</strong><br>{verdict_text}</p>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Family</th><th>Evidence</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>
"""


def write_html(result: ScanResult, path: Path) -> None:
    rows = "".join(
        f"<tr><td class='sev-{f.severity.name}'>{f.severity.name}</td>"
        f"<td>{escape(f.title)}<br><small>{escape(f.detail)}</small></td>"
        f"<td>{escape(f.family or '')}</td>"
        f"<td><code>{escape(', '.join(f'{k}={v}' for k, v in f.evidence.items()))}</code></td></tr>"
        for f in sorted(result.findings, key=lambda f: -f.severity)
    ) or "<tr><td colspan='4'>No findings.</td></tr>"
    d = result.device
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(TEMPLATE.format(
        device=escape(f"{d.get('ro.product.manufacturer')} {d.get('ro.product.model')} - "
                      f"{d.get('ro.build.fingerprint')}"),
        verdict=escape(result.verdict.value.upper()),
        verdict_text=escape(VERDICT_TEXT[result.verdict]),
        rows=rows,
    ), encoding="utf-8")
