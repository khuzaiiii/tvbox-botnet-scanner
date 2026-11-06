"""Record the README demo video of the interactive UI.

Drives `tvbox-scan ui` headlessly against the simulated box in tools/demo_box.py,
captures a frame every 1/fps seconds, renders the frames with a headless Chromium
browser (Edge or Chrome) and encodes them with ffmpeg.

Usage:
    python tools/record_demo.py                      # writes docs/demo/tvbox-scan-demo.{mp4,gif,png}
    python tools/record_demo.py --browser "C:/Program Files/Google/Chrome/Application/chrome.exe"

Needs: the [ui] extra, ffmpeg on PATH, and Edge or Chrome.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tools")]

from demo_box import DemoBox  # noqa: E402
from tvbox_scanner.iocs import load_iocs  # noqa: E402
from tvbox_scanner.ui.app import TvBoxApp  # noqa: E402

SIZE = (130, 40)  # terminal columns x rows
BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "google-chrome", "chromium", "chromium-browser", "microsoft-edge",
]


# --------------------------------------------------------------------------- capture

async def capture_session(frames_dir: Path, work: Path, fps: int) -> tuple[list[tuple[float, str]], str]:
    box = DemoBox()
    # Run from the work dir with relative paths, so no local path (or user name) shows on screen.
    os.chdir(work)
    app = TvBoxApp(lambda serial: box, load_iocs(), serial=None,
                   backup_root=Path("backups"), report_dir=Path("reports"))
    timeline: list[tuple[float, str]] = []
    running = True

    def caption(text: str) -> None:
        app.sub_title = f"DEMO · box simulasi · {text}"

    async with app.run_test(size=SIZE) as pilot:
        start = time.monotonic()

        async def grab() -> None:
            while running:
                svg = app.export_screenshot()
                key = hashlib.sha256(svg.encode()).hexdigest()[:16]  # frame dedup key
                path = frames_dir / f"{key}.svg"
                if not path.exists():
                    path.write_text(svg, encoding="utf-8")
                timeline.append((time.monotonic() - start, key))
                await asyncio.sleep(1 / fps)

        async def hold(seconds: float) -> None:
            await asyncio.sleep(seconds)

        async def settle() -> None:
            await app.workers.wait_for_complete()
            await pilot.pause()

        recorder = asyncio.create_task(grab())

        caption("1. Pilih TV box")
        await pilot.pause()
        await hold(2.2)
        await pilot.press("down")
        await hold(0.6)
        await pilot.press("enter")

        caption("2. Scan (baca sahaja, tiada perubahan)")
        await settle()
        await hold(2.5)

        caption("3. Semak setiap penemuan")
        for _ in range(4):
            await pilot.press("down")
            await hold(0.9)
        await hold(0.8)

        poster = timeline[-1][1]  # findings table with evidence open: the most telling still

        caption("4. Pelan pembuangan: pilih langkah")
        await pilot.press("r")
        await pilot.pause()
        await hold(2.2)
        await pilot.click("#allow-system")
        await hold(1.4)
        app.screen.query_one("#plan").focus()  # the click left focus on the switch
        for _ in range(2):
            await pilot.press("down")
            await hold(0.9)

        caption("5. Sahkan sebelum apa-apa diubah")
        await pilot.click("#apply")
        await pilot.pause()
        await hold(2.4)
        await pilot.click("#yes")

        caption("6. Backup ke PC, kemudian buang")
        await settle()
        await hold(3.0)

        caption("7. Scan semula")
        await pilot.click("#rescan")
        await settle()
        await hold(3.5)

        running = False
        await recorder
    return timeline, poster


# --------------------------------------------------------------------------- render + encode

def find_browser(explicit: str | None) -> str:
    for candidate in ([explicit] if explicit else BROWSERS):
        if candidate and (Path(candidate).exists() or shutil.which(candidate)):
            return shutil.which(candidate) or candidate
    sys.exit("No Edge/Chrome found; pass --browser <path>.")


def render(svg: Path, browser: str, width: int, height: int) -> Path:
    png = svg.with_suffix(".png")
    if png.exists():
        return png
    html = svg.with_suffix(".html")
    html.write_text(
        "<!doctype html><html><head><meta charset='utf-8'><style>html,body{margin:0;padding:0;"
        f"background:#0f111a}}svg{{display:block;width:{width}px;height:{height}px}}</style></head>"
        f"<body>{svg.read_text(encoding='utf-8')}</body></html>",
        encoding="utf-8",
    )
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as profile:
        subprocess.run(
            [browser, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--user-data-dir={profile}",
             f"--window-size={width},{height}", "--virtual-time-budget=3000",
             f"--screenshot={png}", html.as_uri()],
            check=True, capture_output=True, timeout=120,
        )
    return png


def encode(timeline: list[tuple[float, str]], poster_key: str, frames_dir: Path, out_dir: Path) -> None:
    # Collapse consecutive identical frames into one entry with a duration.
    segments: list[tuple[str, float]] = []
    for i, (t, key) in enumerate(timeline):
        end = timeline[i + 1][0] if i + 1 < len(timeline) else t + 0.5
        if segments and segments[-1][0] == key:
            segments[-1] = (key, segments[-1][1] + end - t)
        else:
            segments.append((key, end - t))
    concat = frames_dir / "concat.txt"
    lines = []
    for key, duration in segments:
        lines += [f"file '{(frames_dir / key).with_suffix('.png').as_posix()}'", f"duration {duration:.3f}"]
    lines.append(f"file '{(frames_dir / segments[-1][0]).with_suffix('.png').as_posix()}'")
    concat.write_text("\n".join(lines) + "\n", encoding="utf-8")

    out_dir.mkdir(parents=True, exist_ok=True)
    mp4, gif, poster = out_dir / "tvbox-scan-demo.mp4", out_dir / "tvbox-scan-demo.gif", out_dir / "tvbox-scan-demo.png"
    ff = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y"]
    subprocess.run(ff + ["-f", "concat", "-safe", "0", "-i", str(concat),
                         "-vf", "fps=30,scale=1600:-2:flags=lanczos,format=yuv420p",
                         "-c:v", "libx264", "-crf", "20", "-preset", "slow", "-movflags", "+faststart", str(mp4)],
                   check=True)
    subprocess.run(ff + ["-i", str(mp4), "-vf",
                         "fps=8,scale=1000:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128[p];"
                         "[b][p]paletteuse=dither=bayer:bayer_scale=4", str(gif)], check=True)
    # Poster: the scan result, the most telling single frame.
    shutil.copyfile((frames_dir / poster_key).with_suffix(".png"), poster)
    for f in (mp4, gif, poster):
        print(f"{f}  {f.stat().st_size / 1e6:.1f} MB")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "demo")
    ap.add_argument("--fps", type=int, default=10)
    ap.add_argument("--browser")
    ap.add_argument("--keep", type=Path, help="keep frames in this folder")
    args = ap.parse_args()

    if not shutil.which("ffmpeg"):
        sys.exit("ffmpeg not found on PATH")
    browser = find_browser(args.browser)

    work = Path(tempfile.mkdtemp(prefix="tvbox-demo-"))
    frames_dir = args.keep or work / "frames"
    frames_dir.mkdir(parents=True, exist_ok=True)
    try:
        print("recording UI session...")
        cwd = os.getcwd()
        try:
            timeline, poster = asyncio.run(capture_session(frames_dir, work, args.fps))
        finally:
            os.chdir(cwd)
        unique = sorted({k for _, k in timeline})
        print(f"{len(timeline)} captures, {len(unique)} unique frames, {timeline[-1][0]:.1f}s")

        first = (frames_dir / unique[0]).with_suffix(".svg").read_text(encoding="utf-8")
        vb = first.split('viewBox="', 1)[1].split('"', 1)[0].split()
        width, height = int(float(vb[2])), int(float(vb[3]))

        print(f"rendering with {Path(browser).name} at {width}x{height}...")
        with ThreadPoolExecutor(max_workers=min(6, os.cpu_count() or 2)) as pool:
            list(pool.map(lambda k: render((frames_dir / k).with_suffix(".svg"), browser, width, height), unique))

        print("encoding...")
        encode(timeline, poster, frames_dir, args.out)
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
