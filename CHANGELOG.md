# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-06

First release. Not yet tested on real hardware: all tests run against a simulated box.

### Detection
- Known-IOC scanners for Vo1d, BADBOX 2.0, T95 Corejava and Pandora: installed packages, dropped files
  (with SHA-1/SHA-256 and content markers), running processes, live TCP connections to C2 addresses,
  affected models, test-keys and insecure builds. IOCs from Dr.Web, Nokia Deepfield and DesktopECHO.
- DNS check: Private DNS or DNS servers pointing at a known C2 domain or IP.
- Heuristics (no IOC needed, at most MEDIUM, never removed): processes running from deleted, in-memory or
  world-writable locations; user apps using `com.android.*` names; system-wide HTTP proxy; `su` binaries;
  ports listening on all interfaces, including network ADB.
- Cross-checks for hiding malware: processes in `/proc` missing from `ps`, packages in `packages.xml`
  missing from `pm list packages -u`.
- `--deep` hashes every APK.

### Removal
- Planner and executor: dry run by default, backup to the PC before every delete, `/system` steps only with
  `--allow-system`, stops at the first failure, `actions.json` log.
- `restore` puts back what a `remove --apply` deleted, with original mode and owner.

### Interface
- `tvbox-scan ui`: interactive Textual app in Malay, or English with `--lang en` / `TVBOX_LANG=en`.
- `scan --all` scans every connected box, one report each.
- `scan --redact` masks LAN addresses and proxy settings in JSON/HTML reports for public sharing.
- `compare before.json after.json` shows what is gone, still there or came back after a reboot.
- `doctor`, text/JSON/HTML reports, `export-blocklist` for Pi-hole and routers.

### Project
- `AGENTS.md` playbook so any AI agent can install the tool and walk a person through it.
- CI on Windows, macOS and Linux with Python 3.10 to 3.14, ruff and mypy.
- Weekly ThreatFox IOC update workflow (opens a pull request for review; needs setup).
- Release workflow, issue templates, security policy.

[Unreleased]: https://github.com/khuzaiiii/tvbox-botnet-scanner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/khuzaiiii/tvbox-botnet-scanner/releases/tag/v0.1.0
