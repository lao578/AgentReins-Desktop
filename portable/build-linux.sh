#!/usr/bin/env bash
set -euo pipefail

# Build the Linux Tk desktop shell with PyInstaller.  This script intentionally
# runs on Linux: PyInstaller embeds the host Python runtime and cannot produce a
# reliable Linux binary from Windows or macOS.
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
BUILD_VERSION="${AGENTREINS_VERSION:-0.1.1}"
BUILD_VERSION="${BUILD_VERSION#v}"
BUILD_VERSION="${BUILD_VERSION#V}"
if [[ ! "$BUILD_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$ ]]; then
  echo "AGENTREINS_VERSION must be semantic version text (got '$BUILD_VERSION')." >&2
  exit 2
fi
BUILD_VERSION_DIR="$ROOT/build/agentreins-version"
mkdir -p "$BUILD_VERSION_DIR"
printf 'VERSION = "%s"\n' "$BUILD_VERSION" > "$BUILD_VERSION_DIR/agentreins_build_version.py"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "build-linux.sh must run on Linux (use GitHub Actions for a release build)." >&2
  exit 2
fi

if ! "$PYTHON" -c 'import tkinter' >/dev/null 2>&1; then
  echo "Python tkinter is required (Debian/Ubuntu: sudo apt install python3-tk)." >&2
  exit 2
fi
if ! "$PYTHON" -m PyInstaller --version >/dev/null 2>&1; then
  echo "PyInstaller is required: $PYTHON -m pip install pyinstaller" >&2
  exit 2
fi

if [[ "${1:-}" == "--clean" ]]; then
  rm -rf "$ROOT/build/pyinstaller-linux" "$ROOT/dist/AgentReins"
fi
mkdir -p "$ROOT/build/pyinstaller-linux" "$ROOT/dist"

tray_args=()
if "$PYTHON" -c 'import pystray, PIL' >/dev/null 2>&1; then
  tray_args+=(--hidden-import pystray --hidden-import pystray._xorg --hidden-import PIL --hidden-import PIL.Image --hidden-import PIL.ImageDraw)
fi

"$PYTHON" -m PyInstaller \
  --noconfirm --clean --onedir --windowed \
  --name AgentReins \
  --distpath "$ROOT/dist" \
  --workpath "$ROOT/build/pyinstaller-linux" \
  --specpath "$ROOT/build/pyinstaller-linux" \
  --paths "$BUILD_VERSION_DIR" \
  "${tray_args[@]}" \
  "$ROOT/portable/agentreins_desktop.py"

test -x "$ROOT/dist/AgentReins/AgentReins"
echo "Built $ROOT/dist/AgentReins"
