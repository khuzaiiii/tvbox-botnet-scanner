"""Merge domain/IP IOCs for a ThreatFox tag into an IOC file.

Usage:
    set THREATFOX_AUTH_KEY=...        (free key from https://auth.abuse.ch/)
    python tools/update_iocs.py --tag Vo1d --file src/tvbox_scanner/data/iocs/vo1d.json --dry-run
    python tools/update_iocs.py --tag Vo1d --file src/tvbox_scanner/data/iocs/vo1d.json

Tags on ThreatFox are free text set by each reporter, so always --dry-run first: it lists the
malware families under the tag and every IOC it would add. Narrow with --malware if the tag
mixes families. Only adds entries; never removes any. Review the diff before committing.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path

API = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_tag(tag: str, key: str, limit: int = 1000) -> list[dict]:
    body = json.dumps({"query": "taginfo", "tag": tag, "limit": limit}).encode()
    req = urllib.request.Request(API, data=body, headers={"Auth-Key": key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    if data.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox returned: {data.get('query_status')}")
    return data.get("data") or []


_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
_HEX = {"sha1": re.compile(r"^[0-9a-f]{40}$"), "sha256": re.compile(r"^[0-9a-f]{64}$")}


def parse_entry(entry: dict) -> tuple[str, str] | None:
    """(field, value) for an IOC we can use, or None. ThreatFox data is checked, not trusted:
    a malformed value would otherwise end up in people's block lists."""
    ioc, kind = str(entry.get("ioc", "")).strip().lower(), entry.get("ioc_type", "")
    if kind == "domain":
        return ("domains", ioc) if _DOMAIN.match(ioc) else None
    if kind == "ip:port":
        try:
            ip = ipaddress.ip_address(ioc.rsplit(":", 1)[0].strip("[]"))
        except ValueError:
            return None
        return ("ips", str(ip)) if ip.is_global else None
    for algo in ("sha1", "sha256"):
        if kind == f"{algo}_hash":
            return (algo, ioc) if _HEX[algo].match(ioc) else None
    return None  # urls, md5: not used by the scanner


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--tag", required=True)
    p.add_argument("--file", type=Path, required=True)
    p.add_argument("--malware", action="append", default=[],
                   help="keep only entries whose ThreatFox malware name contains this (repeatable)")
    p.add_argument("--min-confidence", type=int, default=75, help="ThreatFox confidence_level, 0-100")
    p.add_argument("--dry-run", action="store_true", help="show what would be added; change nothing")
    args = p.parse_args()

    key = os.environ.get("THREATFOX_AUTH_KEY")
    if not key:
        print("THREATFOX_AUTH_KEY not set", file=sys.stderr)
        return 2

    doc = json.loads(args.file.read_text(encoding="utf-8"))
    fields = ("domains", "ips", "sha1", "sha256")
    current = {f: set(doc.get(f, [])) for f in fields}
    # Values a reviewer rejected (e.g. reassignable cloud IPs); never re-added.
    excluded = {f: set(doc.get("_excluded", {}).get(f, [])) for f in fields}
    new: dict[str, set[str]] = {f: set() for f in fields}
    families: Counter[str] = Counter()
    skipped: Counter[str] = Counter()

    for entry in fetch_tag(args.tag, key):
        malware = str(entry.get("malware_printable") or entry.get("malware") or "?")
        families[malware] += 1
        if args.malware and not any(m.lower() in malware.lower() for m in args.malware):
            skipped["other malware"] += 1
            continue
        if int(entry.get("confidence_level") or 0) < args.min_confidence:
            skipped["low confidence"] += 1
            continue
        parsed = parse_entry(entry)
        if parsed is None:
            skipped[f"unusable {entry.get('ioc_type')}"] += 1
        elif parsed[1] in excluded[parsed[0]]:
            skipped["excluded by reviewer"] += 1
        elif parsed[1] not in current[parsed[0]]:
            new[parsed[0]].add(parsed[1])

    print(f"tag {args.tag!r}: malware families " + ", ".join(f"{k} ({v})" for k, v in families.most_common()))
    if skipped:
        print("skipped: " + ", ".join(f"{k} ({v})" for k, v in skipped.most_common()))
    for f in fields:
        for value in sorted(new[f]):
            print(f"  + {f:7} {value}")
    added = sum(len(v) for v in new.values())

    if args.dry_run:
        print(f"dry run: would add {added} IOCs to {args.file}")
        return 0
    for f in fields:
        doc[f] = sorted(current[f] | new[f])
    if "https://threatfox.abuse.ch/" not in doc.setdefault("sources", []):
        doc["sources"].append("https://threatfox.abuse.ch/")
    args.file.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"added {added} new IOCs to {args.file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
