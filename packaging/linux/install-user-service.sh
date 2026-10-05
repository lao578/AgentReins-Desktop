#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFIX="${HOME}/.local/lib/agentreins"
BIN_DIR="${HOME}/.local/bin"
SERVICE_DIR="${HOME}/.config/systemd/user"
mkdir -p "$PREFIX" "$BIN_DIR" "$SERVICE_DIR"
install -m 0755 "$ROOT/portable/agentreins_portable.py" "$PREFIX/agentreins-portable"
install -m 0644 "$ROOT/packaging/linux/agentreins.service" "$SERVICE_DIR/agentreins.service"
cat > "$BIN_DIR/agentreins-desktop" <<EOF
#!/usr/bin/env bash
exec python3 "$ROOT/portable/agentreins_desktop.py" "\$@"
EOF
chmod 0755 "$BIN_DIR/agentreins-desktop"
systemctl --user daemon-reload
systemctl --user enable --now agentreins.service
echo "AgentReins user service installed and started."
