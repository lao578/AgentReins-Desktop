#!/usr/bin/env bash
set -euo pipefail

HOST_BINARY="${1:-$(cd "$(dirname "$0")/.." && pwd)/AgentReinsNativeHost}"
HOST_BINARY="$(readlink -f "$HOST_BINARY")"
if [[ ! -x "$HOST_BINARY" ]]; then
  echo "AgentReinsNativeHost was not found or is not executable: $HOST_BINARY" >&2
  exit 1
fi

MANIFEST_NAME="com.agentspec.agentreins.web"
# Native Messaging manifests are JSON.  Escape the two characters that can
# occur in a POSIX path and would otherwise invalidate the manifest.
escaped_host="$(printf '%s' "$HOST_BINARY" | sed 's/\\/\\\\/g; s/"/\\"/g')"
for directory in \
  "$HOME/.config/google-chrome/NativeMessagingHosts" \
  "$HOME/.config/chromium/NativeMessagingHosts" \
  "$HOME/.config/microsoft-edge/NativeMessagingHosts"; do
  mkdir -p "$directory"
  cat > "$directory/$MANIFEST_NAME.json" <<EOF
{
  "name": "$MANIFEST_NAME",
  "description": "AgentReins local web-agent evidence bridge",
  "path": "$escaped_host",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://hcmoeaheokpfbbggdmkdeaiokakiampk/"]
}
EOF
  echo "Installed AgentReins native host: $directory/$MANIFEST_NAME.json"
done
