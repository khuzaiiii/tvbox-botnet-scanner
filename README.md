# tvbox-botnet-scanner

Scan dan buang malware botnet (Vo1d, BADBOX / BADBOX 2.0, T95 Corejava, Pandora) pada Android TV box melalui ADB dari PC.

[![CI](https://github.com/khuzaiiii/tvbox-botnet-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/khuzaiiii/tvbox-botnet-scanner/actions/workflows/ci.yml)

![Demo: scan, semak penemuan, pelan pembuangan, sahkan, buang, scan semula](docs/demo/tvbox-scan-demo.gif)

<sub>Demo guna **box simulasi** (`tools/demo_box.py`) dengan IOC sebenar dari Dr.Web dan Nokia Deepfield; tiada TV
box sebenar dijangkiti atau diubah. Versi MP4: [docs/demo/tvbox-scan-demo.mp4](docs/demo/tvbox-scan-demo.mp4).
Jana semula: `python tools/record_demo.py` (perlukan ffmpeg dan Edge atau Chrome).</sub>

> Guna hanya pada box milik sendiri atau yang anda diberi kebenaran untuk periksa.
> Lihat [Penafian](#penafian) sebelum guna `remove`.

## Cara paling mudah: suruh AI agent anda

Tampal ini ke dalam Claude Code, Codex, Cursor, Copilot atau Gemini CLI:

```
Pasang dan jalankan https://github.com/khuzaiiii/tvbox-botnet-scanner untuk periksa TV box saya
ada botnet atau tidak. Ikut AGENTS.md dalam repo itu langkah demi langkah.
TV box saya: <JENAMA DAN MODEL>
```

Agent akan ikut [AGENTS.md](AGENTS.md): semak model, pasang tool pada komputer, beri langkah tepat untuk
hidupkan debugging pada box anda, scan (baca sahaja), tunjuk pelan, dan hanya buang selepas anda kata "ya".
Prompt penuh (Melayu dan English): [PROMPT.md](PROMPT.md). Masalah biasa: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).
Model yang disebut dalam laporan malware: [docs/DEVICES.md](docs/DEVICES.md).

Tool ini dipasang pada **komputer**, bukan pada TV. Komputer bercakap dengan box melalui ADB (Wi-Fi atau USB).
Tak pernah guna AI agent? Ikut [tutorial di bawah](#tutorial-pasang-guna-ai-agent).

## Tutorial: pasang guna AI agent

Tutorial ini untuk orang yang tak biasa dengan terminal. AI agent akan taip arahan untuk anda; tugas anda
cuma jawab soalan dan tekan butang pada TV.

### Apa yang anda perlukan

- **Komputer** Windows, macOS atau Linux, dalam rangkaian Wi-Fi yang sama dengan TV box (atau kabel USB
  ke box).
- **TV box Android** dan alat kawalan jauhnya. Tool ini tak berfungsi pada Samsung (Tizen), LG (webOS), Roku
  atau Apple TV.
- **AI agent yang boleh jalankan arahan** pada komputer anda, contohnya Claude Code, Codex CLI, Gemini CLI,
  Cursor atau GitHub Copilot (mod agent). Chatbot biasa dalam browser tak boleh: ia tak boleh jalankan arahan.
- Kira-kira 30 minit. Agent akan muat turun Python dan Android platform-tools kalau belum ada (agent akan
  minta izin dulu).

### Langkah 1: Buka agent dalam folder kosong

Buat folder baru, contohnya `tvbox-scan`, kemudian buka AI agent di dalam folder itu. Untuk Claude Code:

```bash
mkdir tvbox-scan
cd tvbox-scan
claude
```

### Langkah 2: Tampal prompt

Tukar `<JENAMA DAN MODEL>` kepada nama box anda (lihat pada kotak, pelekat bawah box, atau
Settings → About), kemudian tampal:

```
Pasang dan jalankan https://github.com/khuzaiiii/tvbox-botnet-scanner untuk periksa TV box saya
ada botnet atau tidak. Ikut AGENTS.md dalam repo itu langkah demi langkah.
TV box saya: <JENAMA DAN MODEL>
```

Versi English dan versi lebih panjang ada dalam [PROMPT.md](PROMPT.md).

### Langkah 3: Jawab soalan agent

Agent akan ikut [AGENTS.md](AGENTS.md). Ini yang biasanya berlaku, dan apa yang anda buat:

| Agent buat | Anda buat |
|---|---|
| Semak model box anda boleh diperiksa atau tidak | Beri jenama dan model, atau gambar skrin About |
| Minta izin muat turun Python, adb dan tool ini | Jawab "ya" kalau setuju |
| Pasang tool, jalankan `tvbox-scan doctor` | Tunggu |
| Terangkan cara hidupkan **Developer options** dan **USB debugging** pada box anda | Ikut satu langkah demi satu pada TV, beritahu apa yang anda nampak |
| Minta alamat IP box | Baca dari Settings → Network pada TV |
| Sambung ke box | Pada TV, tanda **Always allow** dan tekan **OK** pada prompt *Allow USB debugging?* |
| Minta izin scan (baca sahaja, tiada perubahan) | Jawab "ya" |
| Terangkan keputusan dan setiap penemuan | Baca, tanya kalau tak faham |
| Tunjuk pelan pembuangan (dry run, tiada perubahan) | Semak senarai |
| Minta izin buang, dan tanya **berasingan** untuk langkah `/system` | Jawab "ya" hanya kalau anda faham risikonya |
| Reboot box, scan semula, banding keputusan | Beritahu bila box dah kembali ke skrin utama |
| Beri senarai sekatan untuk router, ingatkan matikan debugging | Matikan USB / Network debugging pada TV |

### Peraturan untuk anda

- **Jangan beri kata laluan** (Wi-Fi, Google, router) kepada agent. Tool ini tak perlukannya.
- **Jangan setuju "buang" kalau tak faham.** Scan dan dry run tak mengubah apa-apa; anda boleh berhenti di situ.
- **Langkah `/system` boleh menyebabkan box tak boleh boot (bootloop).** Semua fail di-backup ke folder
  `backups/` dulu, dan `restore` boleh pulangkannya, tapi hanya kalau box masih boleh disambung.
- **Folder `backups/` mengandungi malware sebenar.** Jangan buka, hantar atau muat naik fail di dalamnya.
- **"Tiada padanan IOC" tidak bermaksud box bersih.** Ia hanya bermaksud tiada tanda yang dikenali dijumpai.
- Kalau agent buat sesuatu yang anda tak minta (contohnya root box, flash firmware, atau tambah `--yes` tanpa
  tanya), suruh ia berhenti.

### Kalau tersekat

- Agent tak jumpa box: semak box dan komputer dalam Wi-Fi yang sama, dan prompt pada TV dah diterima.
- Prompt *Allow USB debugging?* tak muncul: matikan dan hidupkan semula USB debugging, kemudian minta agent
  sambung semula.
- Mesej lain: minta agent semak [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md). Kalau masih gagal,
  [buka issue](https://github.com/khuzaiiii/tvbox-botnet-scanner/issues/new?template=bug.yml) dengan apa yang
  dipaparkan.

### Pilihan: skill untuk Claude Code

Kalau anda selalu guna Claude Code, salin `skills/tvbox-botnet-scanner/` ke `~/.claude/skills/`. Selepas itu
cukup taip "periksa TV box saya untuk botnet" dan Claude akan ikut playbook yang sama.

## Pasang sendiri

```bash
git clone https://github.com/khuzaiiii/tvbox-botnet-scanner
cd tvbox-botnet-scanner
powershell -ExecutionPolicy Bypass -File scripts\install.ps1   # Windows
sh scripts/install.sh                                           # macOS / Linux
```

Atau tanpa clone: `uv tool install "tvbox-botnet-scanner[ui] @ git+https://github.com/khuzaiiii/tvbox-botnet-scanner"`
(atau `pipx install` yang sama). Kemudian `tvbox-scan doctor` untuk semak.

## Cara kerja

```
PC (Python 3.10+) --ADB (USB / WiFi)--> TV box
  scan      : IOC dikenali  -> device props, packages, fail, proses, sambungan TCP ke C2, tetapan DNS
              heuristik     -> proses dari folder luar biasa, app pengguna bernama com.android.*, proxy, port terbuka, su
              semakan silang-> /proc lawan ps, packages.xml lawan pm (malware yang menyorok)
  remove    : rancang tindakan (IOC dikenali sahaja) -> dry-run -> backup ke PC -> laksana
  compare   : banding report sebelum dan selepas (apa yang hilang, kekal, kembali)
  blocklist : eksport domain/IP C2 untuk Pi-hole / router
```

## Struktur

```
src/tvbox_scanner/
  adb.py              wrapper adb (shell, pull, kesan root adbd / su)
  models.py           Finding, Severity, ScanResult, Verdict
  iocs.py             loader iocs/*.json
  engine.py           jalankan semua scanner
  scanners/
    device.py         model box, test-keys, ro.secure/ro.debuggable
    packages.py       nama package + hash APK (--deep)
    files.py          fail dropper/payload, skrip boot yang diubah
    processes.py      proses berniat jahat yang sedang berjalan
    network.py        /proc/net/tcp{,6} -> IP C2; DNS / Private DNS yang tunjuk ke C2
    heuristics.py     tanda tanpa IOC (paling tinggi SEDERHANA, tidak pernah dibuang automatik)
    crosscheck.py     tanya box dua cara, tanda kalau jawapan berbeza
  remediation/
    actions.py        Action + tahap risiko (SAFE / MODERATE / DANGEROUS)
    planner.py        finding -> pelan (kill -> rm fail -> buang package)
    executor.py       dry-run lalai, backup sebelum padam, log actions.json
  report/             output teks, JSON, HTML; redact.py sorok IP LAN sebelum kongsi
  compare.py          banding dua report JSON
  i18n.py             teks UI Melayu / English
  blocklist.py        hosts / senarai domain / senarai IP
  data/iocs/          satu JSON untuk setiap famili malware (lihat README di dalamnya)
  ui/                 TUI Textual (pilih device, scan langsung, buang interaktif)
tools/update_iocs.py  tarik IOC dari ThreatFox
tests/                unittest + test UI headless dengan FakeAdb (tiada device diperlukan)
```

## UI interaktif

```bash
tvbox-scan ui                       # pilih device dari senarai / sambung guna IP
tvbox-scan -s 192.168.1.50:5555 ui  # terus ke scan
tvbox-scan ui --lang en             # English (atau set TVBOX_LANG=en)
```

- **Pilih device:** senarai `adb devices`, dan boleh sambung guna IP.
- **Scan:** langkah scan dipapar secara langsung dengan spinner dan bilangan penemuan, jadual penemuan berwarna ikut tahap, panel evidence, dan banner keputusan. Kekunci: `s` scan, `D` deep scan, `r` buang, `w` simpan report HTML/JSON.
- **Buang:** pilih langkah satu per satu. Langkah `/SYSTEM` dikunci sehingga suis diaktifkan. Panel bawah tunjuk arahan dan path backup bagi langkah yang dipilih. Ada butang dry run, dialog pengesahan sebelum laksana, log langsung, butang reboot dan scan semula.
- **Keselamatan:** semua teks dari box dipapar sebagai teks biasa, tidak di-parse sebagai markup Textual.

## Guna (CLI)

```bash
pip install -e .
adb connect 192.168.1.50:5555        # atau sambung guna USB

tvbox-scan devices
tvbox-scan scan --html reports/box.html
tvbox-scan scan --deep                # hash setiap APK, lambat
tvbox-scan scan --json reports/before.json --redact   # sorok IP LAN dan proxy, untuk kongsi di forum
tvbox-scan scan --all --out-dir reports/              # scan semua box yang disambung, satu report setiap box
tvbox-scan remove                     # dry-run: tunjuk apa yang akan dibuat
tvbox-scan remove --apply             # laksana, tanya setiap langkah
tvbox-scan remove --apply --allow-system   # termasuk padam fail dalam /system (perlukan root)
tvbox-scan restore backups/<masa>    # dry-run: tunjuk apa yang akan dipulihkan
tvbox-scan restore backups/<masa> --apply --allow-system   # undo remove (contoh: box bootloop)
tvbox-scan compare reports/before.json reports/after.json  # selepas reboot: apa yang kembali?
tvbox-scan export-blocklist --format domains > badbox.txt
```

Kod keluar `scan` dan `compare`: 0 = tiada penemuan HIGH, 1 = ada (atau kembali), 2 = ralat.

## Had penting

- **`NO_IOC_MATCH` tidak bermaksud bersih.** Scanner hanya kenal IOC yang ada dalam `src/tvbox_scanner/data/iocs/`.
  Heuristik dan semakan silang membantu, tetapi malware baru masih boleh terlepas.
- **Heuristik boleh salah.** Ia hanya menanda (paling tinggi SEDERHANA, keputusan MENCURIGAKAN) dan tidak
  pernah masuk pelan pembuangan. Semak dulu apa benda itu.
- **Tanpa root**, `/data/system` dan sebahagian `/system` tidak kelihatan, dan app sistem hanya boleh
  di-disable untuk user 0. APK masih kekal dalam firmware.
- **Vo1d / BADBOX tertanam dalam firmware.** Factory reset tidak buang malware ini. Lepas `remove`,
  reboot dan scan semula. Kalau ia muncul semula, flash firmware bersih atau ganti box.
- Memadam fail dalam `/system` boleh menyebabkan bootloop. Sebab itu ia perlukan `--allow-system`,
  dan setiap fail di-backup dulu ke `backups/<masa>/`. **Backup tu mengandungi sampel malware.**
- Carian DNS ke domain C2 tidak boleh dilihat dari box (tiada log DNS). Tool ini hanya semak tetapan DNS dan
  sambungan TCP yang sedang terbuka. Sekat domain di router atau Pi-hole guna `export-blocklist`.
- **Belum diuji pada box sebenar.** Semua test guna box simulasi. Kalau anda uji pada box sebenar, sila
  [laporkan](https://github.com/khuzaiiii/tvbox-botnet-scanner/issues/new?template=device-report.yml).

## IOC

Setiap entri dalam fail IOC datang dari sumber awam yang disenaraikan dalam `sources` fail itu.
Senarai penuh dan skema: [src/tvbox_scanner/data/iocs/README.md](src/tvbox_scanner/data/iocs/README.md).

- Vo1d, Pandora: [Dr.Web malware-iocs](https://github.com/DoctorWebLtd/malware-iocs)
- BADBOX 2.0: [Nokia Deepfield](https://github.com/deepfield/public-research/tree/main/ipmoyu)
- T95 / Corejava: [DesktopECHO/T95-H616-Malware](https://github.com/DesktopECHO/T95-H616-Malware)
- Tambahan dari ThreatFox: `THREATFOX_AUTH_KEY=... python tools/update_iocs.py --tag <tag> --file <fail>`.
  Semak tag di threatfox.abuse.ch dulu. Workflow `update-iocs.yml` boleh buat ini setiap minggu dan buka PR
  untuk disemak (lihat komen dalam fail itu untuk setup).

## Rujukan projek

- [VortexisTV/Android-Proxy-Botnet-IOC-Scanner](https://github.com/VortexisTV/Android-Proxy-Botnet-IOC-Scanner)
- [Universal Android Debloater NG](https://github.com/Universal-Debloater-Alliance/universal-android-debloater-next-generation)
- [MVT](https://github.com/mvt-project/mvt)

## Test dan sumbangan

```bash
pip install -e ".[ui]"
python -m unittest discover -s tests -v
ruff check . && mypy
```

Lihat [CONTRIBUTING.md](CONTRIBUTING.md). Jumpa kelemahan keselamatan dalam tool ini? [SECURITY.md](SECURITY.md).
Perubahan setiap versi: [CHANGELOG.md](CHANGELOG.md).

## Penafian

Tool ini disediakan **"seadanya", tanpa sebarang jaminan**, di bawah lesen MIT. Anda menggunakannya atas
risiko sendiri.

- `scan` hanya membaca. Tetapi `remove --apply` mengubah box, dan `--allow-system` memadam fail dalam
  `/system`. Ini boleh menyebabkan box **tidak boleh boot (bootloop)** atau hilang fungsi. Backup dibuat
  sebelum setiap pemadaman dan `tvbox-scan restore` boleh memulihkannya, tetapi tiada jaminan box yang
  sudah bootloop masih boleh dicapai melalui ADB.
- Keputusan `no_ioc_match` **bukan** bukti box bersih. Scanner hanya mengenal penunjuk (IOC) yang disenaraikan
  dalam `src/tvbox_scanner/data/iocs/`, yang diambil daripada laporan awam pada tarikh tertentu. Malware baharu
  atau yang diubah suai mungkin tidak dikesan.
- Malware dalam firmware (Vo1d, BADBOX) selalunya kembali selepas reboot. Penyelesaian yang pasti ialah
  firmware bersih daripada pengeluar atau box lain. Tool ini bukan pengganti kedua-duanya.
- Folder `backups/` mengandungi **sampel malware sebenar**. Jangan buka, jalankan atau kongsi.
- Hanya guna pada peranti milik anda atau yang anda diberi kebenaran untuk periksa. Pengguna bertanggungjawab
  mematuhi undang-undang tempatan.
- Nama jenama dan model disebut hanya kerana ia dinamakan dalam laporan keselamatan awam. Ini bukan dakwaan
  bahawa setiap unit model itu dijangkiti.

**English:** This software is provided "as is", without warranty of any kind (MIT licence). `remove --apply`
and especially `--allow-system` modify the device and can leave it unbootable. A `no_ioc_match` result does
not mean the device is clean. Use only on devices you own or are authorised to inspect, at your own risk.

## Lesen

MIT. Copyright (c) 2026 Khuzaii. Lihat [LICENSE](LICENSE).
