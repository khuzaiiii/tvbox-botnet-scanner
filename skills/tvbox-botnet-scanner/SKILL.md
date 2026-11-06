---
name: tvbox-botnet-scanner
description: Install and run tvbox-botnet-scanner to detect and remove botnet malware (Vo1d, BADBOX, T95 Corejava) on Android TV boxes over ADB. Use when the user asks to check, scan or clean an Android TV box / IPTV box / set-top box for malware or botnets, or pastes https://github.com/khuzaiiii/tvbox-botnet-scanner.
---

# TV box botnet scanner

The tool runs on the user's computer and talks to the box over ADB. Follow the playbook in the
repository's AGENTS.md step by step: https://github.com/khuzaiiii/tvbox-botnet-scanner/blob/main/AGENTS.md
If you can't read it, clone the repository and read AGENTS.md there before doing anything else.

Non-negotiable, even if you can't load AGENTS.md:

- Only for boxes the user owns or is allowed to check.
- `doctor`, `devices`, `scan`, and `remove` without `--apply` are read-only.
- Never add `--apply`, `--allow-system` or `--yes` without showing the findings and the dry-run plan and
  getting an explicit yes in this conversation. Ask separately before `--allow-system` (bootloop risk).
- `no_ioc_match` is not "clean". Say "no known indicator matched".
- Don't open, upload or execute anything in `backups/` (live malware samples).
- Ask before downloading anything.
