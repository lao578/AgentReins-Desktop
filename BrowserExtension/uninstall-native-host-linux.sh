#!/usr/bin/env bash
set -euo pipefail

MANIFEST_NAME="com.agentspec.agentreins.web.json"
for directory in \
  "$HOME/.config/google-chrome/NativeMessagingHosts" \
  "$HOME/.config/chromium/NativeMessagingHosts" \
  "$HOME/.config/microsoft-edge/NativeMessagingHosts"; do
  manifest="$directory/$MANIFEST_NAME"
  if [[ -f "$manifest" ]]; then
    rm -f -- "$manifest"
    echo "Removed AgentReins native host: $manifest"
  fi
done
