#!/usr/bin/env bash
set -euo pipefail
systemctl --user disable --now agentreins.service 2>/dev/null || true
rm -f "$HOME/.config/systemd/user/agentreins.service"
rm -f "$HOME/.local/bin/agentreins-desktop" "$HOME/.local/lib/agentreins/agentreins-portable"
systemctl --user daemon-reload 2>/dev/null || true
echo "AgentReins user service removed. Evidence under ~/.local/share/AgentReins was preserved."
