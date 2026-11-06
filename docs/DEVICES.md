# Devices

Two lists: models **named in public malware reports**, and models **tested with this tool**. Being on the first
list does not mean a given unit is infected, and being absent doesn't mean it's safe. Scan to find out.

## Named in public reports

| Model | Family | Source |
|---|---|---|
| T95, T95Z, T95MAX | BADBOX / T95 Corejava | [DesktopECHO/T95-H616-Malware](https://github.com/DesktopECHO/T95-H616-Malware), [SecurityAffairs](https://securityaffairs.com/140866/security/t95-android-tv-box-malware.html) |
| X88, Q9, X12PLUS, MXQ Pro 5G | BADBOX | [SecurityAffairs](https://securityaffairs.com/140866/security/t95-android-tv-box-malware.html) |
| T95Max (H618), X12-Plus, X88-Pro-10 (RK3328), other AllWinner H616/H618 and RockChip RK3328 boxes | BADBOX / T95 Corejava | [DesktopECHO/T95-H616-Malware](https://github.com/DesktopECHO/T95-H616-Malware) |
| R4 (Android 7.1.2), KJ-SMART4KVIP (Android 10.1), boxes reporting model "TV BOX" | Vo1d | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-vo1d-malware-infects-13-million-android-streaming-boxes/) |
| Boxes running the IPTV apps `com.android.tigertv`, `com.android.mioplus`, `com.android.vo_vivo` and siblings | BADBOX 2.0 (MoYu) | [Nokia Deepfield](https://github.com/deepfield/public-research/tree/main/ipmoyu) |
| Boxes running the IPTV apps `com.world.youcinetv`, `com.global.latinotvod` and others | Pandora | [Dr.Web IOCs](https://github.com/DoctorWebLtd/malware-iocs/blob/d0d45c4/Android.Pandora/README.adoc) |
| AOSP-based boxes in 200+ countries (not Google-certified Android TV) | Vo1d | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-vo1d-malware-infects-13-million-android-streaming-boxes/), [Dr.Web IOCs](https://github.com/DoctorWebLtd/malware-iocs) |

Add a row only with a link to a public report that names the model.

## Tested with this tool

None yet on real hardware. The tool has been tested against a simulated infected box (`tests/fake_adb.py`).

When you test a real box, fill in the [device report](https://github.com/khuzaiiii/tvbox-botnet-scanner/issues/new?template=device-report.yml) or add a row here in a pull request:

| Model | Chip | Android | Root | Connected by | What was tested | Result |
|---|---|---|---|---|---|---|
| | | | | | scan / dry run / remove / remove --allow-system | |

## Developer options, per model

Add notes here when a model hides them somewhere unusual:

- *Most cheap AOSP boxes:* Settings → About → **Build number** × 7, then Developer options → USB debugging.
  Some put About under Settings → Other or Settings → System.
