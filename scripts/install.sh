#!/usr/bin/env sh
# Install tvbox-botnet-scanner into .venv in this folder (macOS, Linux).
# Usage: sh scripts/install.sh
set -eu
cd "$(dirname "$0")/.."

PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
    PY="$cand"; break
  fi
done
if [ -z "$PY" ]; then
  echo "Python 3.10+ not found. Install it with your package manager (e.g. brew install python, sudo apt install python3 python3-venv)." >&2
  exit 1
fi
echo "Using $PY"

"$PY" -m venv .venv
.venv/bin/python -m pip install --upgrade pip --quiet
.venv/bin/python -m pip install ".[ui]" --quiet

if ! command -v adb >/dev/null 2>&1; then
  echo
  echo "adb not found. Install Android platform-tools:"
  echo "  macOS:          brew install --cask android-platform-tools"
  echo "  Debian/Ubuntu:  sudo apt install adb"
  echo "  Fedora:         sudo dnf install android-tools"
  echo "  Arch:           sudo pacman -S android-tools"
fi

echo
.venv/bin/tvbox-scan doctor || true
echo
echo "Run:  .venv/bin/tvbox-scan ui"
