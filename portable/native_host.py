#!/usr/bin/env python3
"""AgentReins Chrome/Edge Native Messaging host for Windows/Linux.

The browser launches this process with a 4-byte little-endian length prefix
followed by one JSON object per message. The host writes an authenticated,
allow-listed event to the same JSONL stream used by the desktop collector and
returns a small acknowledgement using the native-messaging framing protocol.
"""
from __future__ import annotations

import json
import os
import struct
import sys
import threading
from pathlib import Path
from urllib.parse import urlparse

ALLOWED_ORIGIN = "chrome-extension://hcmoeaheokpfbbggdmkdeaiokakiampk/"
ALLOWED_HOSTS = {"grok.com", "gemini.google.com", "chatgpt.com", "claude.ai"}
MAX_MESSAGE_BYTES = 4 * 1024 * 1024
_write_lock = threading.Lock()


def evidence_path() -> Path:
    if sys.platform == "win32":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library/Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return root / "AgentReins" / "web-agent-events.jsonl"


def allowed_event(value: object) -> bool:
    if not isinstance(value, dict) or value.get("schemaVersion") != 1:
        return False
    if not isinstance(value.get("eventId"), str) or not value["eventId"]:
        return False
    if not isinstance(value.get("eventType"), str) or not value["eventType"]:
        return False
    try:
        parsed = urlparse(str(value.get("url", "")))
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    return parsed.scheme == "https" and host in ALLOWED_HOSTS


def write_message(value: dict[str, object]) -> None:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(payload)) + payload)
    sys.stdout.buffer.flush()


def append_event(value: dict[str, object]) -> None:
    destination = evidence_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    # Native hosts are normally one process per browser profile. The lock also
    # protects test harnesses that feed multiple messages concurrently.
    with _write_lock, destination.open("ab") as stream:
        stream.write(line)


def main() -> int:
    # Chrome/Edge pass the extension origin as an argument. Refuse direct
    # launches unless --test is explicitly supplied for local smoke tests.
    args = sys.argv[1:]
    if "--test" not in args and ALLOWED_ORIGIN not in args:
        return 3
    while True:
        header = sys.stdin.buffer.read(4)
        if not header:
            return 0
        if len(header) != 4:
            return 2
        length = struct.unpack("<I", header)[0]
        if length <= 0 or length > MAX_MESSAGE_BYTES:
            write_message({"ok": False, "error": "invalid_message"})
            continue
        payload = sys.stdin.buffer.read(length)
        if len(payload) != length:
            return 2
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            write_message({"ok": False, "error": "invalid_json"})
            continue
        if not allowed_event(value):
            write_message({"ok": False, "error": "evidence_not_allowed"})
            continue
        append_event(value)
        write_message({"ok": True, "eventId": value["eventId"]})


if __name__ == "__main__":
    raise SystemExit(main())
