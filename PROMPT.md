# Prompt untuk AI agent

Tampal salah satu prompt di bawah ke dalam AI agent anda (Claude Code, Codex, Cursor, Copilot, Gemini CLI, atau
mana-mana pembantu yang boleh jalankan arahan terminal). Gunakan komputer yang berada dalam Wi-Fi yang sama
dengan TV box.

Sebelum mula, pada TV box: Settings → About → tekan OK pada **Build number** 7 kali → kembali → Developer
options → hidupkan **USB debugging** (dan **ADB over network** / **Network debugging** jika ada). Biarkan box
hidup.

---

## Bahasa Melayu

```
Pasang dan jalankan https://github.com/khuzaiiii/tvbox-botnet-scanner untuk periksa TV box saya
ada botnet atau tidak. Ikut AGENTS.md dalam repo itu langkah demi langkah.

TV box saya: <JENAMA DAN MODEL, contoh: T95 Max, X96 Mini>

Tanya saya dulu sebelum muat turun apa-apa atau ubah apa-apa pada box. Tunjuk hasil scan dan pelan
pembuangan sebelum buang apa-apa.
```

## English

```
Install and run https://github.com/khuzaiiii/tvbox-botnet-scanner to check my TV box for botnet
malware. Follow AGENTS.md in that repository step by step.

My TV box: <BRAND AND MODEL, e.g. T95 Max, X96 Mini>

Ask me before downloading anything or changing anything on the box. Show me the scan result and the
removal plan before removing anything.
```

---

## Apa yang akan berlaku

1. Agent pasang Python, adb dan tool ini pada komputer anda (ia akan tanya dulu).
2. Agent beri langkah tepat untuk hidupkan debugging pada model box anda.
3. Anda terima prompt **Allow USB debugging?** pada skrin TV.
4. Agent scan box (baca sahaja, tiada perubahan) dan terangkan hasilnya.
5. Kalau dijangkiti: agent tunjuk pelan pembuangan dan tunggu "ya" dari anda. Setiap fail di-backup dulu ke komputer.
6. Reboot, scan semula, dan agent beri senarai blok untuk router anda.
7. Agent ingatkan anda matikan debugging semula.

Lebih suka klik sendiri? Lepas langkah 1, jalankan `tvbox-scan ui` dalam terminal anda.
