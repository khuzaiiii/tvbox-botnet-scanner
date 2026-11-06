"""UI language. The interface text is written in Malay; `t()` swaps in English when asked.

The language is fixed when the UI modules are imported (Textual reads key bindings at
class creation), so call `set_language()` before importing `tvbox_scanner.ui`.
"""

from __future__ import annotations

import os

LANGUAGES = ("ms", "en")


def _pick(lang: str | None) -> str:
    lang = (lang or os.environ.get("TVBOX_LANG") or "ms").lower()[:2]
    return lang if lang in LANGUAGES else "ms"


_lang = _pick(None)


def set_language(lang: str | None) -> None:
    global _lang
    _lang = _pick(lang)


def language() -> str:
    return _lang


def t(text: str) -> str:
    return EN.get(text, text) if _lang == "en" else text


EN = {
    # scan steps
    "Maklumat device": "Device info",
    "Aplikasi terpasang": "Installed apps",
    "Fail sistem (IOC)": "System files (IOC)",
    "Proses berjalan": "Running processes",
    "Sambungan rangkaian": "Network & DNS",
    "Heuristik": "Heuristics",
    "Semakan silang": "Cross-checks",
    # badges and labels
    " ✔ SIAP ": " ✔ DONE ",
    " ✖ GAGAL ": " ✖ FAILED ",
    " LANGKAU ": " SKIPPED ",
    " KRITIKAL ": " CRITICAL ",
    "TINGGI": "HIGH",
    "SEDERHANA": "MEDIUM",
    "RENDAH": "LOW",
    "SELAMAT": "SAFE",
    "TIADA PADANAN IOC": "NO IOC MATCH",
    "Tiada tanda botnet yang dikenali. Ini bukan bukti box bersih: hanya IOC yang disertakan disemak.":
        "No known botnet sign found. This is not proof the box is clean: only the bundled IOCs were checked.",
    "MENCURIGAKAN": "SUSPICIOUS",
    "Ada petunjuk sederhana. Semak penemuan di atas.": "Some medium indicators. Review the findings above.",
    "DIJANGKITI": "INFECTED",
    "Malware berada dalam /data dan boleh dibuang. Tekan 'Buang botnet'.":
        "Malware lives in /data and can be removed. Press 'Remove botnet'.",
    "DIJANGKITI (FIRMWARE)": "INFECTED (FIRMWARE)",
    "Malware tertanam dalam /system. Buang perlukan root dan mungkin kembali selepas reboot; "
    "flash firmware bersih atau ganti box adalah penyelesaian yang pasti.":
        "Malware is built into /system. Removal needs root and may come back after a reboot; "
        "clean firmware or a different box is the reliable fix.",
    # device screen
    "Muat semula": "Refresh",
    "Pilih TV box": "Pick a TV box",
    "Sambung guna kabel USB, atau aktifkan ADB rangkaian pada box dan masukkan IP di bawah.":
        "Connect with a USB cable, or turn on network ADB on the box and enter its IP below.",
    "Sambung": "Connect",
    "Tiada device. Semak kabel / IP, dan benarkan USB debugging pada TV.":
        "No device. Check the cable / IP, and allow USB debugging on the TV.",
    "Pilih device dan tekan Enter.": "Pick a device and press Enter.",
    "Menyambung ke {host}...": "Connecting to {host}...",
    "Device belum dibenarkan. Terima prompt 'Allow USB debugging' pada skrin TV.":
        "Device not authorized yet. Accept the 'Allow USB debugging' prompt on the TV.",
    # scan screen
    "Buang botnet": "Remove botnet",
    "Simpan report": "Save report",
    "Tukar device": "Change device",
    "Langkah scan": "Scan steps",
    "Scan semula": "Scan again",
    "Buang botnet ▶": "Remove botnet ▶",
    "Tahap": "Level",
    "Famili": "Family",
    "Penemuan": "Finding",
    "Sedang scan...": "Scanning...",
    "Sedang scan (deep: hash setiap APK, mungkin lambat)...": "Scanning (deep: hashing every APK, may be slow)...",
    "Ralat scanner": "Scanner error",
    "YA": "YES",
    "TIDAK": "NO",
    "\n{n} penemuan dari {families} famili IOC.": "\n{n} findings from {families} IOC families.",
    "Tiada penemuan.": "No findings.",
    " RALAT ": " ERROR ",
    "Report disimpan": "Report saved",
    # confirm and remove
    "Batal": "Cancel",
    "Sahkan tindakan": "Confirm",
    "Ya, laksana": "Yes, run it",
    "Kembali": "Back",
    "Pelan pembuangan": "Removal plan",
    "Malware dalam firmware. Langkah /SYSTEM boleh menyebabkan bootloop; setiap fail di-backup ke PC dulu.":
        "Malware in firmware. /SYSTEM steps can bootloop the box; every file is backed up to this PC first.",
    "Benarkan ubah /system (risiko bootloop)": "Allow changes to /system (bootloop risk)",
    "Laksana": "Apply",
    "langkah manual": "manual step",
    "perlu root": "needs root",
    "aktifkan suis /system": "turn on the /system switch",
    "{n} langkah dirancang. Pilih langkah, kemudian 'Dry run' atau 'Laksana'.":
        "{n} steps planned. Pick steps, then 'Dry run' or 'Apply'.",
    "Tiada root: hanya app pengguna boleh dibuang; app sistem hanya di-disable untuk user 0.":
        "No root: only user apps can be removed; system apps are only disabled for user 0.",
    "Tiada langkah dipilih.": "No step selected.",
    "{n} langkah akan dijalankan pada ": "{n} steps will run on ",
    "Fail di-backup ke ": "Files are backed up to ",
    " sebelum dipadam.\n": " before they are deleted.\n",
    "\n{n} langkah mengubah /system dan boleh menyebabkan bootloop.\n":
        "\n{n} steps change /system and can bootloop the box.\n",
    "LAKSANA": "APPLY",
    "{n} langkah": "{n} steps",
    "RALAT: ": "ERROR: ",
    "\nSelesai: {done} berjaya, {failed} gagal.": "\nFinished: {done} done, {failed} failed.",
    "Reboot box, kemudian scan semula. Kalau fail muncul semula, malware ada dalam partition yang tool ini tak boleh "
    "bersihkan: flash firmware bersih atau ganti box.":
        "Reboot the box, then scan again. If the files come back, the malware lives in a partition this tool can't "
        "clean: flash clean firmware or replace the box.",
    "Arahan reboot dihantar. Tunggu box hidup, kemudian 'Scan semula'.":
        "Reboot sent. Wait for the box to come back, then 'Scan again'.",
    # app
    "Keluar": "Quit",
    "Tema": "Theme",
}
