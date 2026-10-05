#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec "${PYTHON:-python3}" "$ROOT/portable/agentreins_portable.py" "$@"
