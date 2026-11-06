# Troubleshooting

Look up the message you saw. If it isn't here, stop and tell the person exactly what was printed.
Never "fix" something by disabling, uninstalling, resetting or rooting anything.

## Installing

| You see | Meaning | Do |
|---|---|---|
| `'adb' not found` right after `winget install` | The new PATH only reaches new terminals | Open a new terminal, run `tvbox-scan doctor` again |
| `[FAIL] iocs` | Installed from an old copy, or `--ioc-dir` points somewhere wrong | Reinstall from the repository; don't pass `--ioc-dir` |
| `[WARN] ui textual not installed` | Installed without the `[ui]` extra | CLI still works. For the UI reinstall with `"tvbox-botnet-scanner[ui] @ git+…"` or the install script |
| `externally-managed-environment` from pip | System Python refuses global installs | Use the install script (it makes `.venv/`), `uv tool install` or `pipx install` |

## Connecting

| You see | Meaning | Do |
|---|---|---|
| `unauthorized` in `tvbox-scan devices` | The prompt on the TV wasn't accepted | Ask the person to look at the TV, tick **Always allow**, press OK. If no prompt shows: `adb kill-server`, then connect again |
| `failed to connect` / `Connection refused` | Network debugging is off, or wrong IP | Check the IP on the box (Settings → Network). Ask them to turn on **ADB over network** / **Network debugging**. Some boxes only offer USB: use a cable |
| `No route to host` on macOS while the IP is right | macOS Local Network privacy is blocking the terminal | System Settings → Privacy & Security → Local Network → allow the terminal app, then retry |
| `offline` | ADB on the box is stuck | Ask the person to switch debugging off and on, then connect again |
| Box disappears after a while | Box went to sleep or changed IP | Wake the box; check the IP again |
| `more than one device/emulator` | Several devices connected | Always pass `-s <serial>` |

## Scanning

| You see | Meaning | Do |
|---|---|---|
| `Root : no` / `"root": false` | No root, so `/data/system` and parts of `/system` can't be read | Say the scan was partial. Don't try to root the box |
| `scanner error: ...` at the end | One check failed; the others still ran | Report the message. Results from the other checks are valid |
| Exit code 2 | adb error | Run `tvbox-scan devices`; fix the connection first |
| `--deep` is very slow | It hashes every APK on a slow box | Expected. It's optional |
| Verdict `no_ioc_match` | No known sign matched | Not proof the box is clean. Say so. Suggest the block list and turning debugging off |

## Removing

| You see | Meaning | Do |
|---|---|---|
| `[skipped] ... (needs root)` | Step needs root; box has none | Expected. Firmware infections can't be removed without root: recommend clean firmware or another box |
| `[skipped] ... (dangerous; rerun with --allow-system)` | `/system` step not allowed | Only rerun with `--allow-system` after the person agrees to the bootloop risk |
| `` `pm uninstall ...` failed ... Failure [...] `` | Android refused | Stop. Report it. Don't retry with other flags |
| `` `mount -o rw,remount ...` failed `` | `/system` is read-only (dm-verity or locked firmware) | Can't be cleaned with this tool. Recommend clean firmware or another box |
| `refusing to back up ...: unsafe path component` | The box reported a path that tries to write outside `backups/` on this computer | Treat the box as hostile. Stop removal, don't work around it, tell the person |
| `restore` step says `(original permissions unknown)` | The box's `stat` didn't report mode/owner at backup time | The file is restored with default permissions; a restored boot script may need `chmod 755` |
| Findings come back after reboot | Loader is in a partition the tool can't touch, or a watchdog restored it | Recommend clean firmware or another box; give the block list |
| Box stuck at boot after `--allow-system` | A deleted file was needed to boot | If `tvbox-scan devices` still lists the box (many test-keys boxes start adbd early): `tvbox-scan -s <serial> restore backups/<time> --apply --allow-system`, then reboot. If ADB never comes up, restoring needs recovery mode or reflashing: refer the person to the maker's firmware |
| `error: ... not found; pick a folder created by remove --apply` | Wrong folder given to `restore` | Use the `backups/<time>/` folder that holds `actions.json` |
| `error: ... is the log of an earlier restore` | Pointed `restore` at `restore-log/` | Use the parent `backups/<time>/` folder |
