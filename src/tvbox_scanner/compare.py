"""Compare two JSON scan reports, e.g. before removal and after the reboot."""

from __future__ import annotations

import json
import posixpath
from dataclasses import dataclass, field
from pathlib import Path

HIGH = ("HIGH", "CRITICAL")


class CompareError(ValueError):
    pass


def load_report(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CompareError(f"can't read {path}: {exc}") from exc
    if not isinstance(data, dict) or "verdict" not in data or not isinstance(data.get("findings"), list):
        raise CompareError(f"{path} is not a report from `tvbox-scan scan --json`")
    return data


def finding_key(f: dict) -> tuple[str, str, str]:
    """What makes two findings 'the same' across scans. Process ids change after a reboot,
    so processes are matched by executable name, connections by remote IP."""
    evidence = f.get("evidence") or {}
    kind = f.get("target_type", "")
    if kind == "process":
        ident = posixpath.basename(str(evidence.get("name") or evidence.get("exe") or f.get("target", "")))
    elif kind == "network":
        ident = str(evidence.get("ip") or f.get("target", ""))
    else:
        ident = str(f.get("target", ""))
    return (str(f.get("scanner", "")), kind, ident)


@dataclass
class Comparison:
    before: dict
    after: dict
    gone: list[dict] = field(default_factory=list)
    remaining: list[dict] = field(default_factory=list)
    new: list[dict] = field(default_factory=list)

    @property
    def same_device(self) -> bool:
        keys = ("ro.product.model", "ro.build.fingerprint")
        return all(self.before.get("device", {}).get(k) == self.after.get("device", {}).get(k) for k in keys)

    @property
    def high_left(self) -> list[dict]:
        return [f for f in self.remaining + self.new if f.get("severity") in HIGH]


def compare(before: dict, after: dict) -> Comparison:
    after_keys = {finding_key(f) for f in after["findings"]}
    before_keys = {finding_key(f) for f in before["findings"]}
    return Comparison(
        before=before,
        after=after,
        gone=[f for f in before["findings"] if finding_key(f) not in after_keys],
        remaining=[f for f in after["findings"] if finding_key(f) in before_keys],
        new=[f for f in after["findings"] if finding_key(f) not in before_keys],
    )


def format_comparison(c: Comparison) -> str:
    lines = [f"Verdict: {c.before['verdict']} -> {c.after['verdict']}"]
    if not c.same_device:
        lines.append("WARNING: the two reports are from different models or firmware; are they the same box?")
    for label, items in (("Gone", c.gone), ("Still there", c.remaining), ("New", c.new)):
        lines.append(f"\n{label} ({len(items)}):")
        lines += [f"  [{f.get('severity', '?'):8}] {f.get('title', '')}" for f in items] or ["  -"]
    lines.append("")
    if c.high_left:
        lines.append(f"{len(c.high_left)} HIGH/CRITICAL finding(s) remain or came back. If they survived a reboot, "
                     "the loader lives where this tool can't clean it: reflash clean firmware or replace the box.")
    else:
        lines.append("No HIGH/CRITICAL finding remains. This means no *known* sign matched; it is not proof the box "
                     "is clean.")
    return "\n".join(lines)
