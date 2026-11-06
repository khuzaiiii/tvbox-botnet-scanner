# Security policy

## Reporting a problem in this tool

Report privately through
[GitHub private vulnerability reporting](https://github.com/khuzaiiii/tvbox-botnet-scanner/security/advisories/new),
not in a public issue. Expect a first reply within 7 days.

Useful to include: the version (`tvbox-scan version`), the command, and what a malicious box would have to
send to trigger the problem.

## Threat model

The box being scanned may be fully controlled by malware with root. Everything it returns (`getprop`, `pm`,
`ps`, file contents, paths, serial numbers) is treated as hostile input. In scope:

- A box causing the tool to write outside `backups/` or `reports/` on the computer
  (guarded by `safe_backup_path` in `remediation/executor.py`).
- A box injecting markup or actions into the interactive UI (all device text goes through `ui/widgets.plain()`).
- A box causing commands other than the planned ones to run, on the box or on the computer.
- Anything that makes `remove` delete without a backup, or skip `--apply` / `--allow-system`.
- Report output (HTML) that runs script from device-supplied text.

Out of scope: the malware itself hiding from detection (that's a detection gap: open a normal issue or a
"New IOC" issue), and attacks that need control of the computer running the tool.

## Not a security issue, but please don't

- Don't attach files from `backups/` anywhere. They are live malware samples.
- Don't post unredacted scan reports publicly; use `scan --redact`.
