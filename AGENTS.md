# Instructions for AI agents

You are helping someone check their own Android TV box (or Android TV) for botnet malware —
Vo1d, BADBOX / BADBOX 2.0, the T95 "Corejava" family — and remove it if they agree.

**The tool runs on the person's computer, not on the TV.** You install it on the computer, the
computer talks to the box over ADB (Wi-Fi or USB), scans it, and can remove what it finds.

This file is the playbook. It is written for any AI model, large or small, and any brand of box.
Follow it in order. Read [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) before you improvise a fix.

## First: check the device, before anything else

As soon as you know the brand and model (the person names it, or it is on a photo or sticker), check it
**before** installing anything or asking for an IP address:

| The device runs | What this tool can do | Follow |
|---|---|---|
| **Android** (cheap Android TV boxes: T95, X96, H96, MXQ, TX3, X88, Q9 …, Android TV / Google TV sets and sticks, Android projectors, IPTV boxes running Android) | Scan, and remove what it finds | Steps 1 to 7 |
| Fire TV (Amazon) | Scan; removal of user apps only | Steps 1 to 7; `/system` steps will not apply |
| Samsung Tizen, LG webOS, Roku, Hisense VIDAA, Apple TV | Nothing: no ADB, and these families are not what this malware targets | Stop and say so |

- How to tell: Settings → About shows an Android version, or `tvbox-scan devices` lists it once connected.
  If unsure, ask for a photo of the About screen. Never start "to see if it works".
- [docs/DEVICES.md](docs/DEVICES.md) lists models named in public reports and models tested with this tool.
  Tell the person which list their model is in, and don't promise more than that.

## How to follow this playbook

- Do the steps in order, one at a time. Don't skip ahead or merge steps.
- Run **one command per shell call** and read its output before the next one.
- Every step ends with a **Check**. If it fails, stop. Look the message up in
  [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md); if it isn't there, tell the person exactly what you saw.
- Replace every `<serial>`, `<ip>`, `<os>` with a real value. Never run a line that still contains `<` `>`.
- Ask questions the person can answer with yes/no or by reading the TV screen. Never ask them to type commands.
- Talk to the person in their own language. This tool's interactive screen (`tvbox-scan ui`) is in Malay.
- When unsure, the answer is always: change nothing and ask.

## Ground rules

1. **Only boxes the person owns or is allowed to check.** If that's unclear, ask.
2. **Read-only first.** `doctor`, `devices`, `scan`, and `remove` *without* `--apply` change nothing on the box.
3. **Never add `--apply`, `--allow-system` or `--yes` on your own.** First show the findings and the dry-run
   plan, say what each step does and that files are backed up first, and wait for an explicit yes in this
   conversation. Ask again, separately, before `--allow-system`: it deletes files in `/system` and can leave
   the box stuck at boot (bootloop).
4. **Never call a box "clean".** The verdict `no_ioc_match` means no *known* sign matched. Say exactly that.
5. **Firmware infections don't go away for good.** For `infected_firmware`, tell the person that removal needs
   root, may come back after a reboot, and that clean firmware from the maker or a different box is the
   reliable fix. Don't look for workarounds such as rooting the box yourself or flashing firmware.
6. **`backups/` holds live malware.** Don't open, upload, run or attach anything from it.
7. **Downloads need a yes.** Name what you will download, from where, and roughly how big, before installing
   Python, Android platform-tools or this tool.
8. **Credentials stay with the person.** They accept prompts on the TV and type any pairing codes themselves.

## Step by step

### 1. Install the tool on the computer

- Check Python: `python3 --version` (Windows: `py -3 --version`). Need 3.10 or newer. If missing, ask, then:
  Windows `winget install --id Python.Python.3.12 -e`, macOS `brew install python`,
  Debian/Ubuntu `sudo apt install python3 python3-venv`.
- Check adb: `adb version`. If missing, ask, then install Android platform-tools:

  | OS | Command |
  |---|---|
  | Windows | `winget install --id Google.PlatformTools -e` (then open a new terminal) |
  | macOS | `brew install --cask android-platform-tools` |
  | Debian / Ubuntu | `sudo apt install adb` |
  | Fedora | `sudo dnf install android-tools` |
  | Arch | `sudo pacman -S android-tools` |
  | Other | <https://developer.android.com/tools/releases/platform-tools> |

- Get the tool. If this repository is already cloned, run the install script from its root:
  - Windows: `powershell -ExecutionPolicy Bypass -File scripts\install.ps1`
  - macOS / Linux: `sh scripts/install.sh`

  The script makes `.venv/` and installs the tool there. From then on the command is
  `.venv\Scripts\tvbox-scan.exe` (Windows) or `.venv/bin/tvbox-scan` (macOS, Linux); this file writes it
  as `tvbox-scan`.

  Not cloned? Either `git clone https://github.com/khuzaiiii/tvbox-botnet-scanner` and run the script, or
  install it as a tool:
  `uv tool install "tvbox-botnet-scanner[ui] @ git+https://github.com/khuzaiiii/tvbox-botnet-scanner"`
  (or the same with `pipx install`).
- **Check**: `tvbox-scan doctor` prints `[OK  ]` for `python`, `iocs` and `adb`. A `WARN` on `devices` is
  expected at this point.

### 2. Turn on debugging on the box

Every brand hides developer settings somewhere else. Before telling the person what to press:

1. Get the exact model (About screen, box sticker) and Android version.
2. Look in [docs/DEVICES.md](docs/DEVICES.md) for notes on that model.
3. Otherwise search the web for "<brand> <model> developer options" and use a source about that model.
4. Tell the person one step at a time and ask what they see after each.

The usual paths:
- **Cheap Android boxes:** Settings → About (sometimes Settings → Other → About) → press OK on
  **Build number** 7 times → back → Developer options → **USB debugging** on. Many also have
  **ADB over network** / **Network debugging**: turn it on too.
- **Android TV / Google TV:** Settings → Device Preferences → About → press OK on **Build** 7 times →
  Developer options → **USB debugging** on (and Network debugging if shown). Newer ones show
  **Wireless debugging** with a pairing code: ask for the code and `ip:port`, then `adb pair <ip>:<port>`.

Then ask for the box's IP address (Settings → Network → the connected network).

- **Check**: the person confirms debugging is on and gives an IP address (or says they will use a USB cable).

### 3. Connect

- Over Wi-Fi: `adb connect <ip>:5555`. Tell the person an **Allow USB debugging?** prompt will appear on the
  TV; they tick **Always allow** and press OK. Then run `adb connect <ip>:5555` once more.
- Over USB: plug the cable from the computer into the box's USB-OTG port, then accept the same prompt.
- **Check**: `tvbox-scan devices` shows the box with state `device`. `unauthorized` means the prompt was not
  accepted; `offline` or nothing means see TROUBLESHOOTING, "Connecting". Use the first column as `<serial>`.

### 4. Scan (read-only)

- Ask: "May I scan the box now? It only reads, nothing changes." Wait for yes.
- `tvbox-scan -s <serial> scan --json reports/scan.json --html reports/scan.html`
- Exit code 0 = no high finding, 1 = infected, 2 = adb error (see TROUBLESHOOTING).
- Read `reports/scan.json`. Tell the person, in plain words: the `verdict`, each finding with severity
  `HIGH` or `CRITICAL`, and whether the scan ran with root (`"root": true`). Without root, files under
  `/data/system` can't be seen, so say the scan was partial.
- Findings from the `heuristics` and `crosscheck` scanners match no known IOC. They are at most `MEDIUM`, can
  be false alarms, and are never removed by this tool. Describe them as "worth a look", not as malware.
- If the person wants to post the report publicly (forum, issue), rerun with `--redact`: it masks LAN IPs and
  proxy settings.
- **Check**: `reports/scan.json` exists and has a `verdict`.

If the person prefers to click through it themselves, tell them to run `tvbox-scan ui` in their own terminal
(it is a full-screen app; don't run it inside your tool). It shows the same scan and lets them pick what to
remove.

### 5. Show the removal plan (dry run)

Only if the verdict is `infected_removable`, `infected_firmware` or `suspicious`:

- `tvbox-scan -s <serial> remove`
- This changes nothing. It prints each planned step, with `[dry-run]`, `[skipped]` and a reason.
- Explain each step to the person: what it removes, that the file or app is copied to `backups/` first, and
  which steps are skipped (no root, or `/system` steps that need `--allow-system`).
- **Check**: the output ends with a list of steps and no `failed`.

### 6. Remove (only with an explicit yes)

- Ask: "Shall I run these steps? Each file is backed up to this computer first." Wait for yes.
- `tvbox-scan -s <serial> remove --apply --yes`
  (`--yes` is allowed here only because the person just approved this exact plan.)
- Only if the plan has `/system` steps, the box has root, **and** the person agrees after hearing that it can
  bootloop the box: `tvbox-scan -s <serial> remove --apply --yes --allow-system`
- **Check**: every applied step shows `[done    ]`. On `[failed  ]` stop: the tool stops at the first failure
  on purpose. Report the message; don't retry with different flags.
- Note the backup folder it printed (`backups/<time>/`). If anything stops working after removal, `restore`
  undoes it: `tvbox-scan -s <serial> restore backups/<time>` (dry run), then with `--apply` (and
  `--allow-system` for `/system` files) only after the person agrees. Restoring brings back what was flagged
  as malware, so use it to recover a broken box, not by default.

### 7. Reboot, scan again, protect the network

- Ask, then: `adb -s <serial> reboot`. Wait until the person says the box is back on the home screen, then
  `adb connect <ip>:5555` again if they use Wi-Fi.
- `tvbox-scan -s <serial> scan --json reports/after.json`
- `tvbox-scan compare reports/scan.json reports/after.json`
  It lists findings that are gone, still there, or new. Exit code 1 means a `HIGH`/`CRITICAL` finding remains
  or came back: the loader lives where this tool can't clean it. Say so, and recommend clean firmware from the
  maker or a different box. Exit code 0 still isn't "clean": say no *known* sign matched.
- Offer a block list for their router, Pi-hole or AdGuard Home (blocks the botnet's servers even when the
  malware can't be removed): `tvbox-scan export-blocklist --format domains > blocklist.txt`. Note: the shipped
  list may be short; it only holds indicators from public sources.
- Remind them to turn **USB debugging / Network debugging off** when done: an open ADB port is how a lot of
  these boxes get infected in the first place.
- **Check**: the person has the final verdict, knows where `reports/` and `backups/` are, and debugging is off.

## Working on this repository

```bash
pip install -e ".[ui]"
python -m unittest discover -s tests
```

- Tests use `tests/fake_adb.py`; no device needed.
- IOCs live in `src/tvbox_scanner/data/iocs/*.json`. Every entry must trace to a public source listed in that
  file's `sources`. Never invent hashes, domains, IPs or package names.
- Everything read from the box is attacker-controlled: keep it out of host paths (`safe_backup_path`) and
  render it in the UI only through `ui/widgets.plain()`.
- A tested model goes into [docs/DEVICES.md](docs/DEVICES.md) with what was tested.
