#!/usr/bin/env bash
set -euo pipefail

# Compatibility entry point. The maintained Linux packaging implementation is
# portable/package-linux.sh; keep this path for existing scripts and links.
ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
exec "$ROOT/portable/package-linux.sh" "${1:-all}"
