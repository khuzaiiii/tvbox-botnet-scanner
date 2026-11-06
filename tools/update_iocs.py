"""Merge domain/IP IOCs for a ThreatFox tag into an IOC file.

Usage:
    set THREATFOX_AUTH_KEY=...        (free key from https://auth.abuse.ch/)
    python tools/update_iocs.py --tag BADBOX --file src/tvbox_scanner/data/iocs/badbox2.json

Only adds entries; never removes ones already in the file. Review the diff before committing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
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


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--tag", required=True)
    p.add_argument("--file", type=Path, required=True)
    args = p.parse_args()

    key = os.environ.get("THREATFOX_AUTH_KEY")
    if not key:
        print("THREATFOX_AUTH_KEY not set", file=sys.stderr)
        return 2

    doc = json.loads(args.file.read_text(encoding="utf-8"))
    domains, ips = set(doc.get("domains", [])), set(doc.get("ips", []))
    sha1, sha256 = set(doc.get("sha1", [])), set(doc.get("sha256", []))
    before = len(domains) + len(ips) + len(sha1) + len(sha256)

    for entry in fetch_tag(args.tag, key):
        ioc, kind = entry.get("ioc", ""), entry.get("ioc_type", "")
        if kind == "domain":
            domains.add(ioc.lower())
        elif kind == "ip:port":
            ips.add(ioc.rsplit(":", 1)[0])
        elif kind == "sha1_hash":
            sha1.add(ioc.lower())
        elif kind == "sha256_hash":
            sha256.add(ioc.lower())

    doc["domains"], doc["ips"] = sorted(domains), sorted(ips)
    doc["sha1"], doc["sha256"] = sorted(sha1), sorted(sha256)
    if "https://threatfox.abuse.ch/" not in doc.setdefault("sources", []):
        doc["sources"].append("https://threatfox.abuse.ch/")
    args.file.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    added = len(domains) + len(ips) + len(sha1) + len(sha256) - before
    print(f"added {added} new IOCs to {args.file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
