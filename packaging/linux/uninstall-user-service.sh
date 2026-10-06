#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFIX="${HOME}/.local/lib/agentreins"
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now agentreins.service 2>/dev/null || true
fi

# Remove Native Messaging registrations before deleting the stable host path.
# Keep evidence under ~/.local/share/AgentReins by design.
UNINSTALLER="$PREFIX/uninstall-native-host-linux.sh"
[ -x "$UNINSTALLER" ] || UNINSTALLER="$ROOT/BrowserExtension/uninstall-native-host-linux.sh"
[ -x "$UNINSTALLER" ] && "$UNINSTALLER" || true
rm -f "$HOME/.config/systemd/user/agentreins.service"
rm -f "$HOME/.local/bin/agentreins-desktop" "$HOME/.local/bin/agentreins-install-service" \
  "$HOME/.local/bin/agentreins-uninstall-service"
rm -rf "$PREFIX"
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user daemon-reload 2>/dev/null || true
fi
echo "AgentReins user service removed. Evidence under ~/.local/share/AgentReins was preserved."
