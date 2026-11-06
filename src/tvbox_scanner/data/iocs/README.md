# IOC files

One JSON file per malware family. All `*.json` files in this folder are loaded.

| Field | Type | Used by |
|---|---|---|
| `family` | string | all |
| `sources` | list of URLs | every IOC must trace back to one of these (pin a commit where possible) |
| `packages` | list of `"name"` or `{name, severity, note}` | `scanners/packages.py` |
| `files` | list of `{path, severity, note, kind?, content_markers?}` | `scanners/files.py` |
| `sha1`, `sha256` | lists of lowercase hex digests | APK hashes (`--deep`) and file hashes; a match raises severity to CRITICAL |
| `process_names` | list of executable names | `scanners/processes.py` (basename match, so avoid generic names) |
| `domains` | list | `export-blocklist` only (the box has no DNS log) |
| `ips` | list | `scanners/network.py`, `export-blocklist`. Only dedicated C2 IPs, never shared CDN or hosting front-ends |
| `device_models` | list of model names | `scanners/device.py`, whole-word match on `ro.product.model`; MEDIUM, never conclusive |

- `kind`: `any` (default), `file` or `dir`. Use it when a known cleanup replaces the payload with the
  opposite type (the T95 "vaccine" turns the `Corejava` folder into a locked empty file), so a vaccinated
  box stops matching.
- `content_markers`: for legit files that malware modifies (e.g. `install-recovery.sh`). The file only counts
  as a hit if its content contains one of the markers.
- Keys starting with `_` are ignored.

## Where the shipped IOCs come from

| File | Source |
|---|---|
| `vo1d.json` | Dr.Web `malware-iocs` (commit d0d45c4), Dr.Web analysis on Habr, BleepingComputer |
| `pandora.json` | Dr.Web `malware-iocs` (commit d0d45c4) |
| `badbox2.json` | Nokia Deepfield `public-research/ipmoyu` (commit 854e703). HUMAN's 109-domain list is not included yet: its site blocks automated download |
| `t95_corejava.json` | DesktopECHO `T95-H616-Malware` README (commit fd32162) |

Add to them by hand from the original reports, or with
`THREATFOX_AUTH_KEY=... python tools/update_iocs.py --tag <tag> --file src/tvbox_scanner/data/iocs/<family>.json`.
Never copy indicators from secondhand articles without checking the original.
