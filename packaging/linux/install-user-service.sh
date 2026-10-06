#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFIX="${HOME}/.local/lib/agentreins"
BIN_DIR="${HOME}/.local/bin"
SERVICE_DIR="${HOME}/.config/systemd/user"
DATA_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/AgentReins"
mkdir -p "$PREFIX" "$BIN_DIR" "$SERVICE_DIR" "$DATA_DIR"
# Evidence contains prompts/tool arguments; keep the data directory private
# even when the invoking shell uses a permissive umask.
chmod 700 "$DATA_DIR"

# Copy the complete source-side portable runtime.  The old installer copied
# only agentreins_portable.py, which starts successfully from a checkout but
# fails as a user service because its NativeSessionReader dependency was not
# installed next to it.  Keeping the modules together also makes the desktop
# launcher independent from the source checkout after installation.
for module in "$ROOT"/portable/*.py; do
  [ -f "$module" ] || continue
  install -m 0644 "$module" "$PREFIX/$(basename "$module")"
done
chmod 0755 "$PREFIX/agentreins_portable.py"
cat > "$PREFIX/agentreins-portable" <<EOF
#!/usr/bin/env bash
exec python3 "$PREFIX/agentreins_portable.py" "\$@"
EOF
chmod 0755 "$PREFIX/agentreins-portable"
install -m 0644 "$ROOT/packaging/linux/agentreins.service" "$SERVICE_DIR/agentreins.service"
cat > "$BIN_DIR/agentreins-desktop" <<EOF
#!/usr/bin/env bash
exec python3 "$PREFIX/agentreins_desktop.py" "\$@"
EOF
chmod 0755 "$BIN_DIR/agentreins-desktop"

# Register the browser bridge when a locally built host is available.  This
# is intentionally best-effort: the collector/service remains useful on
# machines where no browser or Native Messaging binary was built.
HOST_SOURCE="${AGENTREINS_NATIVE_HOST:-$ROOT/dist/AgentReinsNativeHost}"
HOST_INSTALLER="$ROOT/BrowserExtension/install-native-host-linux.sh"
if [ -f "$HOST_SOURCE" ] && [ -x "$HOST_INSTALLER" ]; then
  install -m 0755 "$HOST_SOURCE" "$PREFIX/AgentReinsNativeHost"
  install -m 0755 "$HOST_INSTALLER" "$PREFIX/install-native-host-linux.sh"
  install -m 0755 "$ROOT/BrowserExtension/uninstall-native-host-linux.sh" \
    "$PREFIX/uninstall-native-host-linux.sh"
  "$PREFIX/install-native-host-linux.sh" "$PREFIX/AgentReinsNativeHost"
else
  echo "Native host binary not found; browser integration was not registered."
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl is required for the user service; files were installed but the service was not started." >&2
  exit 2
fi
systemctl --user daemon-reload
systemctl --user enable --now agentreins.service
echo "AgentReins user service installed and started."
