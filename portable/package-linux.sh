#!/usr/bin/env bash
set -euo pipefail

# Produce Linux distribution artifacts:
#   * AppImage containing the PyInstaller desktop app
#   * Debian amd64 package containing the app, CLI collector and user service
#
# Usage: package-linux.sh [all|appimage|deb]
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
VERSION="${AGENTREINS_VERSION:-}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo 0.1.1)"
fi
VERSION="${VERSION#v}"
VERSION="${VERSION//[^A-Za-z0-9.+~-]/-}"
export AGENTREINS_VERSION="$VERSION"
ARCH="${AGENTREINS_ARCH:-x86_64}"
OUT="$ROOT/dist"
BUILD="$ROOT/build/linux-package"
APPDIR="$BUILD/AppDir"
MODE="${1:-all}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "package-linux.sh must run on Linux (use GitHub Actions for a release build)." >&2
  exit 2
fi
if [[ "$MODE" != all && "$MODE" != appimage && "$MODE" != deb ]]; then
  echo "usage: $0 [all|appimage|deb]" >&2
  exit 2
fi

if [[ "$MODE" == all || "$MODE" == appimage ]]; then
  "$ROOT/portable/build-linux.sh"
fi
mkdir -p "$OUT" "$BUILD"

make_appdir() {
  rm -rf "$APPDIR"
  mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications"
  cp -a "$OUT/AgentReins" "$APPDIR/usr/bin/AgentReins"
  if [[ -f "$ROOT/Assets/agentreins-logo.png" ]]; then
    cp "$ROOT/Assets/agentreins-logo.png" "$APPDIR/agentreins.png"
  fi
  cat > "$APPDIR/AppRun" <<'EOF'
#!/usr/bin/env sh
set -eu
APPDIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec "$APPDIR/usr/bin/AgentReins/AgentReins" "$@"
EOF
  chmod +x "$APPDIR/AppRun"
  cat > "$APPDIR/usr/share/applications/agentreins.desktop" <<'EOF'
[Desktop Entry]
Name=AgentReins
Comment=Local-first AI agent evidence console
Exec=AgentReins
Terminal=false
Type=Application
Categories=Utility;System;
Icon=agentreins
EOF
  # appimagetool discovers the launcher from the AppDir root. Keep the
  # freedesktop-standard copy under usr/share/applications as well.
  cp "$APPDIR/usr/share/applications/agentreins.desktop" "$APPDIR/agentreins.desktop"
}

make_appimage() {
  make_appdir
  local tool="${APPIMAGETOOL:-}"
  if [[ -z "$tool" ]]; then
    tool="$(command -v appimagetool || true)"
  fi
  if [[ -z "$tool" ]]; then
    local cache="$BUILD/appimagetool-$ARCH.AppImage"
    if [[ ! -x "$cache" ]]; then
      local url
      case "$ARCH" in
        x86_64|amd64) url="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" ;;
        aarch64|arm64) url="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-aarch64.AppImage" ;;
        *) echo "Unsupported AppImage architecture: $ARCH" >&2; return 2 ;;
      esac
      command -v curl >/dev/null || { echo "curl is required to download appimagetool" >&2; return 2; }
      curl --fail --location --retry 3 --output "$cache" "$url"
      chmod +x "$cache"
    fi
    tool="$cache"
  fi
  local output="$OUT/AgentReins-${VERSION}-Linux-${ARCH}.AppImage"
  # GitHub-hosted runners may not expose FUSE. Newer AppImages honor this
  # variable and self-extract instead of trying to mount their runtime.
  APPIMAGE_EXTRACT_AND_RUN=1 ARCH="$ARCH" "$tool" "$APPDIR" "$output"
  chmod +x "$output"
  sha256sum "$output" > "$output.sha256"
  echo "Created $output"
}

make_deb() {
  command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required" >&2; return 2; }
  local root="$BUILD/deb-root"
  rm -rf "$root"
  mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/usr/lib/agentreins" \
    "$root/usr/share/applications" "$root/usr/share/icons/hicolor/512x512/apps" \
    "$root/usr/lib/systemd/user" \
    "$root/usr/share/doc/agentreins"
  if [[ ! -x "$OUT/AgentReins/AgentReins" ]]; then
    "$ROOT/portable/build-linux.sh"
  fi
  cp -a "$OUT/AgentReins" "$root/usr/lib/agentreins/AgentReins"
  cp "$ROOT/portable/agentreins_portable.py" "$root/usr/lib/agentreins/agentreins_portable.py"
  cp "$ROOT/portable/agent_adapters.py" "$root/usr/lib/agentreins/agent_adapters.py"
  if [[ -f "$ROOT/Assets/agentreins-logo.png" ]]; then
    cp "$ROOT/Assets/agentreins-logo.png" "$root/usr/share/icons/hicolor/512x512/apps/agentreins.png"
  fi
  cat > "$root/usr/bin/agentreins" <<'EOF'
#!/usr/bin/env sh
set -eu
exec /usr/lib/agentreins/AgentReins/AgentReins "$@"
EOF
  cat > "$root/usr/bin/agentreins-portable" <<'EOF'
#!/usr/bin/env sh
set -eu
exec /usr/bin/python3 /usr/lib/agentreins/agentreins_portable.py "$@"
EOF
  chmod +x "$root/usr/bin/agentreins" "$root/usr/bin/agentreins-portable"
  cat > "$root/usr/share/applications/agentreins.desktop" <<'EOF'
[Desktop Entry]
Name=AgentReins
Comment=Local-first AI agent evidence console
Exec=agentreins
Terminal=false
Type=Application
Categories=Utility;System;
Icon=agentreins
EOF
  cat > "$root/usr/lib/systemd/user/agentreins.service" <<'EOF'
[Unit]
Description=AgentReins local evidence collector
After=graphical-session.target

[Service]
Type=simple
ExecStart=/usr/bin/agentreins-portable watch --interval 2 --output %h/.local/share/AgentReins/evidence.jsonl
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
  cat > "$root/usr/share/doc/agentreins/README.Debian" <<'EOF'
AgentReins stores evidence at ~/.local/share/AgentReins/evidence.jsonl.

Enable the per-user collector after installation:
  systemctl --user daemon-reload
  systemctl --user enable --now agentreins.service

Stop/disable it with:
  systemctl --user disable --now agentreins.service
EOF
  cat > "$root/DEBIAN/control" <<EOF
Package: agentreins
Version: $VERSION
Section: utils
Priority: optional
Architecture: amd64
Maintainer: AgentReins contributors
Description: Local-first AI agent evidence console
 AgentReins observes local process and network metadata and writes JSONL evidence.
 It never captures packet payloads or requires root privileges.
EOF
  cat > "$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
  chmod 0755 "$root/DEBIAN/postinst"
  local output="$OUT/AgentReins-${VERSION}-Linux-amd64.deb"
  dpkg-deb --build --root-owner-group "$root" "$output" >/dev/null
  sha256sum "$output" > "$output.sha256"
  echo "Created $output"
}

case "$MODE" in
  all) make_appimage; make_deb ;;
  appimage) make_appimage ;;
  deb) make_deb ;;
esac
