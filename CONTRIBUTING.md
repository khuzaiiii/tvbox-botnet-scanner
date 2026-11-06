# Contributing

## The most useful thing: test on a real box

The tool has only been tested against a simulated box. If you own an Android TV box, run a scan (read-only)
and fill in the [device report](https://github.com/khuzaiiii/tvbox-botnet-scanner/issues/new?template=device-report.yml).
Results from clean boxes are just as useful: they show where the tool raises false alarms.

## Development setup

```bash
git clone https://github.com/khuzaiiii/tvbox-botnet-scanner
cd tvbox-botnet-scanner
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[ui]" ruff mypy
python -m unittest discover -s tests -v
ruff check . && mypy
```

No device is needed: tests use `tests/fake_adb.py`. `tools/demo_box.py` is a stateful simulated box used to
record the README demo (`python tools/record_demo.py`, needs ffmpeg and Edge or Chrome).

## Rules

- **IOCs need a public source.** Every hash, domain, IP, package or path in `src/tvbox_scanner/data/iocs/`
  must appear in a report listed in that file's `sources`. Never add indicators from memory or guesswork:
  a wrong entry makes people delete things from their box and block innocent servers.
- **Device output is hostile.** Anything read from the box goes into host paths only through
  `safe_backup_path`, into the UI only through `ui/widgets.plain()`, and into shell commands only after
  validation (see how `crosscheck.py` checks a pid is all digits).
- **Nothing is removed without a known IOC.** Heuristic and cross-check findings stay at `MEDIUM` or below
  so the planner (which acts on `HIGH`+) ignores them.
- **Never call a box clean** in output or docs. `no_ioc_match` means no known sign matched.
- **UI text** is written in Malay and wrapped in `t()`; add the English to `src/tvbox_scanner/i18n.py`.
  A test fails if a translation is missing.
- Add a test for each behaviour change. Add a line to `CHANGELOG.md` under "Unreleased".

## Releasing

1. Move the "Unreleased" notes in `CHANGELOG.md` under a new version heading.
2. Bump `version` in `pyproject.toml` and `src/tvbox_scanner/__init__.py`.
3. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`. The release workflow builds, tests and
   creates the GitHub release; PyPI upload runs only if the `PUBLISH_TO_PYPI` variable is `true`.
