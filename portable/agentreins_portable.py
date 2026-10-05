#!/usr/bin/env python3
"""Cross-platform, dependency-free AgentReins evidence collector.

The macOS application remains the rich SwiftUI console.  This companion is
the Windows/Linux runtime: it records the same high-value first-party signals
(agent processes, parent lineage, and open TCP destinations) as JSONL, without
requiring a GUI toolkit, SQLite development headers, or elevated privileges.

Examples:
    python portable/agentreins_portable.py snapshot
    python portable/agentreins_portable.py watch --interval 2 --output evidence.jsonl
    python portable/agentreins_portable.py paths
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import platform
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional


SCHEMA_VERSION = 1
AGENT_MARKERS = {
    # The desktop ChatGPT host is the Codex runtime in the macOS adapter too.
    "codex": ("codex", "chatgpt", "openai.chatgpt"),
    "claude": ("claude",),
    "cursor": ("cursor",),
    "qoder": ("qoder",),
    "workbuddy": ("workbuddy",),
    "kiro": ("kiro",),
    "windsurf": ("windsurf", "codeium"),
    "trae": ("trae",),
    "aider": ("aider",),
}


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    ppid: int
    command: str
    executable: str = ""
    agent: Optional[str] = None


@dataclass(frozen=True)
class NetworkRecord:
    pid: Optional[int]
    local: str
    remote: str
    state: str = ""
    protocol: str = "tcp"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def platform_paths() -> dict[str, str]:
    """Return portable data/config paths, matching native OS conventions."""
    home = Path.home()
    system = platform.system().lower()
    if system == "windows":
        data = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        config = data
        cache = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
    elif system == "darwin":
        data = home / "Library/Application Support"
        config = home / "Library/Preferences"
        cache = home / "Library/Caches"
    else:
        data = Path(os.environ.get("XDG_DATA_HOME", home / ".local/share"))
        config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        cache = Path(os.environ.get("XDG_CACHE_HOME", home / ".cache"))
    return {
        "home": str(home),
        "data": str(data / "AgentReins"),
        "config": str(config / "AgentReins"),
        "cache": str(cache / "AgentReins"),
        "evidence": str(data / "AgentReins" / "evidence.jsonl"),
        "webEvidence": str(data / "AgentReins" / "web-agent-events.jsonl"),
    }


def _run(command: list[str], timeout: float = 8.0) -> str:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True,
                                   errors="replace", timeout=timeout)
        return completed.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _agent_for(command: str) -> Optional[str]:
    lower = command.lower()
    for agent, markers in AGENT_MARKERS.items():
        if any(marker in lower for marker in markers):
            return agent
    return None


def _linux_processes() -> list[ProcessRecord]:
    result: list[ProcessRecord] = []
    proc = Path("/proc")
    for item in proc.iterdir() if proc.exists() else []:
        if not item.name.isdigit():
            continue
        try:
            stat = (item / "stat").read_text(errors="replace")
            # The command name is enclosed in parentheses and may contain spaces.
            close = stat.rfind(")")
            fields = stat[close + 2 :].split()
            ppid = int(fields[1]) if len(fields) > 1 else 0
            raw = (item / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
            executable = ""
            try:
                executable = os.readlink(item / "exe")
            except OSError:
                pass
            command = raw or executable or stat[stat.find("(") + 1 : close]
            pid = int(item.name)
            result.append(ProcessRecord(pid, ppid, command, executable, _agent_for(command)))
        except (OSError, ValueError, IndexError):
            continue
    return result


def _windows_processes() -> list[ProcessRecord]:
    # CIM gives parent PID and a full command line, unlike tasklist.  Use
    # ConvertTo-Json so parsing remains independent of PowerShell formatting.
    script = "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
    output = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], timeout=15)
    if not output:
        output = _run(["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command", script], timeout=15)
    try:
        rows = json.loads(output)
        if isinstance(rows, dict):
            rows = [rows]
    except json.JSONDecodeError:
        rows = []
    result: list[ProcessRecord] = []
    for row in rows if isinstance(rows, list) else []:
        try:
            pid = int(row.get("ProcessId", 0))
            ppid = int(row.get("ParentProcessId", 0))
        except (TypeError, ValueError):
            continue
        name = str(row.get("Name") or "")
        executable = str(row.get("ExecutablePath") or "")
        command = str(row.get("CommandLine") or executable or name)
        result.append(ProcessRecord(pid, ppid, command, executable, _agent_for(" ".join((name, executable, command)))))
    return result


def _windows_processes_tasklist() -> list[ProcessRecord]:
    """Best-effort fallback when CIM is disabled by local policy."""
    output = _run(["tasklist", "/FO", "CSV", "/NH"], timeout=8)
    result: list[ProcessRecord] = []
    for row in csv.reader(output.splitlines()):
        if len(row) < 2:
            continue
        try:
            pid = int(row[1])
        except ValueError:
            continue
        name = row[0]
        result.append(ProcessRecord(pid, 0, name, name, _agent_for(name)))
    return result


def _posix_processes() -> list[ProcessRecord]:
    # ps is available on Linux containers without procfs and on BSD/macOS.
    output = _run(["ps", "-axo", "pid=,ppid=,command="], timeout=8)
    result: list[ProcessRecord] = []
    for line in output.splitlines():
        match = re.match(r"\s*(\d+)\s+(\d+)\s+(.*)", line)
        if not match:
            continue
        pid, ppid, command = int(match.group(1)), int(match.group(2)), match.group(3).strip()
        result.append(ProcessRecord(pid, ppid, command, command.split(" ", 1)[0], _agent_for(command)))
    return result


def processes() -> list[ProcessRecord]:
    system = platform.system().lower()
    if system == "linux":
        result = _linux_processes()
        return result or _posix_processes()
    if system == "windows":
        return _windows_processes() or _windows_processes_tasklist()
    return _posix_processes()


def _parse_endpoint(value: str) -> str:
    # ss and netstat use IPv6 ``[::1]:443`` or ``::1:443`` forms.
    value = value.strip()
    if value in {"*", "*:0", "0.0.0.0:*", "[::]:*"}:
        return value
    return value


def _linux_network() -> list[NetworkRecord]:
    output = _run(["ss", "-H", "-tanp"], timeout=8)
    result: list[NetworkRecord] = []
    for line in output.splitlines():
        columns = line.split()
        if len(columns) < 5 or columns[0].lower() not in {"tcp", "tcp6"}:
            continue
        state, local, remote = columns[1], columns[4], columns[5]
        pid = None
        owner = " ".join(columns[6:]) if len(columns) > 6 else ""
        match = re.search(r"pid=(\d+)", owner)
        if match:
            pid = int(match.group(1))
        if remote.endswith(":*") or remote in {"*:*", "0.0.0.0:0", "[::]:0"}:
            continue
        result.append(NetworkRecord(pid, _parse_endpoint(local), _parse_endpoint(remote), state, "tcp"))
    return result


def _windows_network() -> list[NetworkRecord]:
    script = "Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort,State | ConvertTo-Json -Compress"
    output = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], timeout=15)
    if not output:
        output = _run(["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command", script], timeout=15)
    try:
        rows = json.loads(output)
        if isinstance(rows, dict):
            rows = [rows]
    except json.JSONDecodeError:
        rows = []
    result: list[NetworkRecord] = []
    for row in rows if isinstance(rows, list) else []:
        try:
            pid = int(row.get("OwningProcess", 0)) or None
            local = f"{row.get('LocalAddress', '')}:{int(row.get('LocalPort', 0))}"
            remote = f"{row.get('RemoteAddress', '')}:{int(row.get('RemotePort', 0))}"
        except (TypeError, ValueError):
            continue
        if remote.endswith(":0"):
            continue
        result.append(NetworkRecord(pid, local, remote, str(row.get("State") or ""), "tcp"))
    return result


def _posix_network() -> list[NetworkRecord]:
    output = _run(["lsof", "-n", "-P", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pn"], timeout=8)
    result: list[NetworkRecord] = []
    current: Optional[int] = None
    for line in output.splitlines():
        if line.startswith("p"):
            try:
                current = int(line[1:])
            except ValueError:
                current = None
        elif line.startswith("n") and current is not None and "->" in line:
            local, remote = line[1:].split("->", 1)
            result.append(NetworkRecord(current, local, remote, "ESTABLISHED", "tcp"))
    return result


def network() -> list[NetworkRecord]:
    system = platform.system().lower()
    if system == "linux":
        return _linux_network() or _posix_network()
    if system == "windows":
        return _windows_network()
    return _posix_network()


def agent_summary(items: Iterable[ProcessRecord]) -> list[dict[str, object]]:
    groups: dict[str, list[ProcessRecord]] = {}
    for item in items:
        if item.agent:
            groups.setdefault(item.agent, []).append(item)
    return [
        {"id": agent, "processIds": sorted(x.pid for x in rows), "instances": len(rows), "confidence": "inferred"}
        for agent, rows in sorted(groups.items())
    ]


def snapshot() -> dict[str, object]:
    procs = processes()
    return {
        "schemaVersion": SCHEMA_VERSION,
        "timestamp": utc_now(),
        "platform": platform.system().lower(),
        "collector": "agentreins-portable",
        "capabilities": ["processExecution", "processLineage", "networkConnection"],
        "processes": [asdict(item) for item in procs],
        "connections": [asdict(item) for item in network()],
        "agents": agent_summary(procs),
    }


def write_snapshot(record: dict[str, object], output: Optional[Path]) -> None:
    # ASCII-only JSON avoids PowerShell 5/OEM code-page rewriting bytes while
    # piping a large snapshot. Unicode values remain lossless via ``\\u`` escapes.
    line = json.dumps(record, ensure_ascii=True, sort_keys=True)
    if output is None:
        # Windows PowerShell commonly exposes the active code page (cp936)
        # through stdout. Evidence is UTF-8 regardless of the console locale.
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(line, flush=True)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="AgentReins Windows/Linux headless collector")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("snapshot", help="collect and print one JSON snapshot")
    paths = sub.add_parser("paths", help="print platform data directories")
    watch = sub.add_parser("watch", help="append periodic snapshots as JSONL")
    watch.add_argument("--interval", type=float, default=2.0, help="seconds between snapshots (minimum 0.25)")
    watch.add_argument("--output", type=Path, help="JSONL destination; stdout when omitted")
    args = parser.parse_args(argv)
    if args.command == "paths":
        print(json.dumps(platform_paths(), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.command == "snapshot":
        write_snapshot(snapshot(), None)
        return 0
    interval = max(0.25, args.interval)
    try:
        while True:
            started = time.monotonic()
            write_snapshot(snapshot(), args.output)
            time.sleep(max(0, interval - (time.monotonic() - started)))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
