#!/usr/bin/env bash
set -euo pipefail

# Produce Linux distribution artifacts:
#   * AppImage containing the PyInstaller desktop app
#   * Debian package containing the app, CLI collector and user service
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
# ``git describe --always`` can return a bare commit id when no tag exists.
# Keep ad-hoc/source builds usable by converting that value into a Debian and
# PyInstaller-compatible development version instead of passing an invalid
# package version to dpkg-deb.
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$ ]]; then
  VERSION="0.0.0+${VERSION#-}"
fi
export AGENTREINS_VERSION="$VERSION"
ARCH="${AGENTREINS_ARCH:-$(uname -m)}"
case "$ARCH" in
  amd64|x86_64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="aarch64" ;;
esac
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

# The browser extension talks to a Native Messaging executable, not to the
# desktop process.  Build that executable on Linux as part of the package so
# AppImage and Debian users do not have to install a second Python runtime.
# Keep it separate from build-linux.sh because the desktop build is windowed
# while a native host must retain a console/stdin/stdout pipe.
build_native_host() {
  rm -f "$OUT/AgentReinsNativeHost"
  "$PYTHON" -m PyInstaller \
    --noconfirm --clean --onefile --console \
    --name AgentReinsNativeHost \
    --distpath "$OUT" \
    --workpath "$BUILD/pyinstaller-native-host" \
    --specpath "$BUILD/pyinstaller-native-host" \
    "$ROOT/portable/native_host.py"
  test -x "$OUT/AgentReinsNativeHost"
}

if [[ "$MODE" == all || "$MODE" == appimage || "$MODE" == deb ]]; then
  build_native_host
  sha256sum "$OUT/AgentReinsNativeHost" > "$OUT/AgentReinsNativeHost.sha256"
fi

make_appdir() {
  rm -rf "$APPDIR"
  mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/lib/agentreins" \
    "$APPDIR/usr/share/applications" "$APPDIR/usr/share/agentreins/BrowserExtension"
  cp -a "$OUT/AgentReins" "$APPDIR/usr/bin/AgentReins"
  cp "$OUT/AgentReinsNativeHost" "$APPDIR/usr/lib/agentreins/AgentReinsNativeHost"
  chmod 0755 "$APPDIR/usr/lib/agentreins/AgentReinsNativeHost"
  cp -a "$ROOT/BrowserExtension/." "$APPDIR/usr/share/agentreins/BrowserExtension/"
  chmod 0755 "$APPDIR/usr/share/agentreins/BrowserExtension/install-native-host-linux.sh"
  chmod 0755 "$APPDIR/usr/share/agentreins/BrowserExtension/uninstall-native-host-linux.sh"
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
  # A stable launcher keeps the AppImage mount path out of the generated
  # manifests.  Users can run this from the AppImage's extracted directory or
  # pass the host path to the script directly.
  cat > "$APPDIR/usr/bin/agentreins-install-native-host" <<'EOF'
#!/usr/bin/env sh
set -eu
APPDIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
exec "$APPDIR/usr/share/agentreins/BrowserExtension/install-native-host-linux.sh" \
  "$APPDIR/usr/lib/agentreins/AgentReinsNativeHost"
EOF
  chmod +x "$APPDIR/usr/bin/agentreins-install-native-host"
  cat > "$APPDIR/usr/bin/agentreins-uninstall-native-host" <<'EOF'
#!/usr/bin/env sh
set -eu
APPDIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
exec "$APPDIR/usr/share/agentreins/BrowserExtension/uninstall-native-host-linux.sh"
EOF
  chmod +x "$APPDIR/usr/bin/agentreins-uninstall-native-host"
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
  cp "$OUT/AgentReinsNativeHost" "$root/usr/lib/agentreins/AgentReinsNativeHost"
  chmod 0755 "$root/usr/lib/agentreins/AgentReinsNativeHost"
  mkdir -p "$root/usr/share/agentreins/BrowserExtension"
  cp -a "$ROOT/BrowserExtension/." "$root/usr/share/agentreins/BrowserExtension/"
  chmod 0755 "$root/usr/share/agentreins/BrowserExtension/install-native-host-linux.sh"
  chmod 0755 "$root/usr/share/agentreins/BrowserExtension/uninstall-native-host-linux.sh"
  cp "$ROOT/portable/agentreins_portable.py" "$root/usr/lib/agentreins/agentreins_portable.py"
  cp "$ROOT/portable/agent_adapters.py" "$root/usr/lib/agentreins/agent_adapters.py"
  # Keep the source-side modules next to the portable CLI as well as in the
  # frozen desktop binary.  The CLI/runtime imports provider_config and
  # process_rules lazily, so omitting them would make a Debian install fail
  # only when those views are first requested.
  for module in operations_runtime.py operations_cli.py turn_journal.py evidence_projection.py safety_features.py update_checker.py provider_config.py process_rules.py; do
    if [[ -f "$ROOT/portable/$module" ]]; then
      cp "$ROOT/portable/$module" "$root/usr/lib/agentreins/$module"
    fi
  done
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
  cat > "$root/usr/bin/agentreins-install-native-host" <<'EOF'
#!/usr/bin/env sh
set -eu
exec /usr/share/agentreins/BrowserExtension/install-native-host-linux.sh \
  /usr/lib/agentreins/AgentReinsNativeHost
EOF
  cat > "$root/usr/bin/agentreins-uninstall-native-host" <<'EOF'
#!/usr/bin/env sh
set -eu
exec /usr/share/agentreins/BrowserExtension/uninstall-native-host-linux.sh
EOF
  cat > "$root/usr/bin/agentreins-install-service" <<'EOF'
#!/usr/bin/env sh
set -eu
if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl is required for the AgentReins user service" >&2
  exit 2
fi
systemctl --user daemon-reload
systemctl --user enable --now agentreins.service
echo "AgentReins collector service enabled for the current user."
EOF
  cat > "$root/usr/bin/agentreins-uninstall-service" <<'EOF'
#!/usr/bin/env sh
set -eu
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now agentreins.service 2>/dev/null || true
  systemctl --user daemon-reload 2>/dev/null || true
fi
echo "AgentReins collector service disabled. Evidence was preserved."
EOF
  chmod +x "$root/usr/bin/agentreins" "$root/usr/bin/agentreins-portable" \
    "$root/usr/bin/agentreins-install-native-host" \
    "$root/usr/bin/agentreins-uninstall-native-host" \
    "$root/usr/bin/agentreins-install-service" \
    "$root/usr/bin/agentreins-uninstall-service"
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
ExecStart=/usr/bin/agentreins-portable watch --interval 2 --output %h/.local/share/AgentReins/evidence.jsonl --database %h/.local/share/AgentReins/evidence.sqlite3
Restart=on-failure
RestartSec=5
UMask=0077

[Install]
WantedBy=default.target
EOF
  cat > "$root/usr/share/doc/agentreins/README.Debian" <<'EOF'
AgentReins stores evidence at ~/.local/share/AgentReins/evidence.jsonl.

The optional browser Native Messaging host is installed with:
  agentreins-install-native-host
This writes per-user Chrome, Chromium, and Microsoft Edge manifests. Install
the packaged BrowserExtension directory into the browser if needed.
Remove those manifests with `agentreins-uninstall-native-host`.

Enable the per-user collector after installation:
  agentreins-install-service
  # (equivalent to systemctl --user enable --now agentreins.service)

Stop/disable it with:
  agentreins-uninstall-service
EOF
  local deb_arch="${AGENTREINS_DEB_ARCH:-}"
  if [[ -z "$deb_arch" ]]; then
    deb_arch="$(dpkg --print-architecture 2>/dev/null || true)"
  fi
  if [[ -z "$deb_arch" ]]; then
    case "$ARCH" in
      x86_64|amd64) deb_arch="amd64" ;;
      aarch64|arm64) deb_arch="arm64" ;;
      *) echo "Unable to determine Debian architecture for $ARCH" >&2; return 2 ;;
    esac
  fi
  cat > "$root/DEBIAN/control" <<EOF
Package: agentreins
Version: $VERSION
Section: utils
Priority: optional
Architecture: $deb_arch
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
  local output="$OUT/AgentReins-${VERSION}-Linux-${deb_arch}.deb"
  dpkg-deb --build --root-owner-group "$root" "$output" >/dev/null
  sha256sum "$output" > "$output.sha256"
  echo "Created $output"
}

case "$MODE" in
  all) make_appimage; make_deb ;;
  appimage) make_appimage ;;
  deb) make_deb ;;
esac
