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
import ctypes
import datetime as dt
import json
import os
import platform
import re
import select
import sqlite3
import struct
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional


VERSION = os.environ.get("AGENTREINS_VERSION", "0.1.0").lstrip("v")
SCHEMA_VERSION = 2
INTERNAL_EVIDENCE_NAMES = {
    "evidence.jsonl", "evidence.sqlite3", "evidence.sqlite3-wal", "evidence.sqlite3-shm", "web-agent-events.jsonl"
}
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


@dataclass(frozen=True)
class FileChangeRecord:
    path: str
    action: str
    source: str
    timestamp: str
    is_directory: bool = False


class WebEvidenceReader:
    """Incrementally read browser Native-Messaging events from JSONL.

    The browser bridge is deliberately append-only. Keeping the byte offset
    here lets the CLI and desktop watcher ingest only new events on each
    refresh without rereading the entire history.
    """

    def __init__(self, path: Path):
        self.path = path
        self.offset = 0
        self._fingerprint: tuple[int, int] | None = None

    def poll(self) -> list[dict[str, object]]:
        try:
            stat = self.path.stat()
        except OSError:
            return []
        fingerprint = (int(stat.st_ino), int(stat.st_size))
        # Handle truncation or replacement of the append-only log.
        if self._fingerprint and (fingerprint[0] != self._fingerprint[0] or fingerprint[1] < self.offset):
            self.offset = 0
        self._fingerprint = fingerprint
        events: list[dict[str, object]] = []
        try:
            with self.path.open("rb") as handle:
                handle.seek(self.offset)
                for raw in handle:
                    self.offset += len(raw)
                    try:
                        value = json.loads(raw.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if isinstance(value, dict):
                        events.append(value)
        except OSError:
            return []
        return events


class EvidenceStore:
    """Small WAL-backed evidence store shared by the CLI and desktop shell."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(path), timeout=10)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS snapshots(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                platform TEXT NOT NULL,
                process_count INTEGER NOT NULL,
                connection_count INTEGER NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS file_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                path TEXT NOT NULL,
                action TEXT NOT NULL,
                source TEXT NOT NULL,
                is_directory INTEGER NOT NULL,
                details TEXT
            );
            CREATE TABLE IF NOT EXISTS web_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                provider TEXT,
                session_id TEXT,
                turn_id TEXT,
                tool_call_id TEXT,
                observed_at TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions(
                session_id TEXT PRIMARY KEY,
                agent TEXT,
                provider TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0,
                metadata TEXT
            );
            CREATE TABLE IF NOT EXISTS tool_calls(
                tool_call_id TEXT PRIMARY KEY,
                session_id TEXT,
                turn_id TEXT,
                tool_name TEXT NOT NULL,
                status TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence_links(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_kind TEXT NOT NULL,
                source_id TEXT NOT NULL,
                session_id TEXT,
                turn_id TEXT,
                tool_call_id TEXT,
                confidence TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(source_kind, source_id, session_id, turn_id, tool_call_id)
            );
        """)
        self.connection.commit()

    def append_snapshot(self, record: dict[str, object]) -> int:
        cursor = self.connection.execute(
            "INSERT INTO snapshots(timestamp,platform,process_count,connection_count,payload) VALUES(?,?,?,?,?)",
            (str(record.get("timestamp", utc_now())), str(record.get("platform", "unknown")),
             len(record.get("processes") or []), len(record.get("connections") or []),
             json.dumps(record, ensure_ascii=True, sort_keys=True)),
        )
        snapshot_id = int(cursor.lastrowid)
        timestamp = str(record.get("timestamp", utc_now()))
        for agent in record.get("agents") or []:
            if not isinstance(agent, dict):
                continue
            agent_id = str(agent.get("id") or "unknown")
            session_id = f"process:{agent_id}"
            metadata = json.dumps({"processIds": agent.get("processIds") or []}, ensure_ascii=True, sort_keys=True)
            self.connection.execute(
                "INSERT INTO sessions(session_id,agent,provider,first_seen,last_seen,event_count,metadata) VALUES(?,?,?,?,?,1,?) "
                "ON CONFLICT(session_id) DO UPDATE SET last_seen=excluded.last_seen,event_count=sessions.event_count+1,metadata=excluded.metadata",
                (session_id, agent_id, "local-process", timestamp, timestamp, metadata),
            )
            self.link_evidence("snapshot", str(snapshot_id), {"session_id": session_id}, "inferred")
        self.connection.commit()
        return snapshot_id

    def append_file_events(self, events: Iterable[FileChangeRecord], context: Optional[dict[str, object]] = None) -> list[int]:
        ids: list[int] = []
        for event in events:
            cursor = self.connection.execute(
                "INSERT INTO file_events(timestamp,path,action,source,is_directory,details) VALUES(?,?,?,?,?,?)",
                (event.timestamp, event.path, event.action, event.source, int(event.is_directory), "{}"),
            )
            ids.append(int(cursor.lastrowid))
            if context:
                self.link_evidence("file_event", str(cursor.lastrowid), context, "inferred")
        if ids:
            self.connection.commit()
        return ids

    def append_web_events(self, events: Iterable[dict[str, object]]) -> list[str]:
        """Persist browser events and project sessions/tool calls.

        Web events are kept lossless in ``web_events`` while the derived
        tables provide stable joins for a future UI or SQL report.
        """
        accepted: list[str] = []
        for event in events:
            event_id = str(event.get("eventId") or "")
            if not event_id:
                continue
            event_type = str(event.get("eventType") or "unknown")
            timestamp = str(event.get("timestamp") or event.get("receivedAt") or utc_now())
            provider = str(event.get("provider") or "") or None
            session_id = str(event.get("sessionId") or (f"{provider}:web" if provider else "")) or None
            turn_id = str(event.get("turnId") or (event_id if event_type == "prompt" else "")) or None
            tool_call_id = str(event.get("toolCallId") or (event_id if event_type in {"upload", "tool", "tool_call", "tool_result"} else "")) or None
            payload = json.dumps(event, ensure_ascii=True, sort_keys=True)
            cursor = self.connection.execute(
                "INSERT OR IGNORE INTO web_events(event_id,event_type,provider,session_id,turn_id,tool_call_id,observed_at,payload) VALUES(?,?,?,?,?,?,?,?)",
                (event_id, event_type, provider, session_id, turn_id, tool_call_id, timestamp, payload),
            )
            if cursor.rowcount == 0:
                continue
            accepted.append(event_id)
            if session_id:
                self.connection.execute(
                    "INSERT INTO sessions(session_id,agent,provider,first_seen,last_seen,event_count,metadata) VALUES(?,?,?,?,?,1,?) "
                    "ON CONFLICT(session_id) DO UPDATE SET last_seen=excluded.last_seen,event_count=sessions.event_count+1,metadata=COALESCE(excluded.metadata,sessions.metadata)",
                    (session_id, provider, provider, timestamp, timestamp, json.dumps({"source": "web-native-messaging"})),
                )
            if tool_call_id:
                tool_name = str(event.get("toolName") or ("browser.upload" if event_type == "upload" else event_type))
                status = "completed" if event_type in {"upload", "tool_result", "response"} else "observed"
                self.connection.execute(
                    "INSERT INTO tool_calls(tool_call_id,session_id,turn_id,tool_name,status,first_seen,last_seen,payload) VALUES(?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(tool_call_id) DO UPDATE SET last_seen=excluded.last_seen,status=excluded.status,payload=excluded.payload",
                    (tool_call_id, session_id, turn_id, tool_name, status, timestamp, timestamp, payload),
                )
            if session_id or tool_call_id:
                self.link_evidence("web_event", event_id, {
                    "session_id": session_id, "turn_id": turn_id, "tool_call_id": tool_call_id,
                }, "confirmed")
        if accepted:
            self.connection.commit()
        return accepted

    def link_evidence(self, source_kind: str, source_id: str, context: dict[str, object], confidence: str) -> None:
        self.connection.execute(
            "INSERT OR IGNORE INTO evidence_links(source_kind,source_id,session_id,turn_id,tool_call_id,confidence,created_at) VALUES(?,?,?,?,?,?,?)",
            (source_kind, source_id, context.get("session_id"), context.get("turn_id"), context.get("tool_call_id"), confidence, utc_now()),
        )

    def latest_context(self) -> Optional[dict[str, object]]:
        tool = self.connection.execute(
            "SELECT tool_call_id,session_id,turn_id FROM tool_calls WHERE session_id IS NOT NULL ORDER BY last_seen DESC LIMIT 1"
        ).fetchone()
        if tool:
            return {
                "session_id": str(tool[1]),
                "turn_id": str(tool[2]) if tool[2] else None,
                "tool_call_id": str(tool[0]),
            }
        row = self.connection.execute(
            "SELECT session_id FROM sessions ORDER BY last_seen DESC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        session_id = str(row[0])
        tool = self.connection.execute(
            "SELECT tool_call_id,turn_id FROM tool_calls WHERE session_id=? ORDER BY last_seen DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        return {
            "session_id": session_id,
            "turn_id": str(tool[1]) if tool and tool[1] else None,
            "tool_call_id": str(tool[0]) if tool else None,
        }

    def latest_web_context(self) -> Optional[dict[str, object]]:
        row = self.connection.execute(
            "SELECT session_id,turn_id,tool_call_id FROM web_events ORDER BY observed_at DESC,id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        return {"session_id": row[0], "turn_id": row[1], "tool_call_id": row[2]}

    def close(self) -> None:
        self.connection.close()


class LinuxInotifyWatcher:
    """Low-level recursive inotify watcher with no external dependency.

    inotify watches directories rather than trees.  Register the existing
    subtree at startup and add watches for directories created later so a
    project that creates nested workspaces does not silently lose events.
    """

    MASK = 0x00000100 | 0x00000200 | 0x00000040 | 0x00000080 | 0x00000004 | 0x00000002
    IN_ISDIR = 0x40000000
    IN_IGNORED = 0x00008000

    def __init__(self, paths: Iterable[Path]):
        self.fd = -1
        self.watches: dict[int, Path] = {}
        if platform.system().lower() != "linux":
            return
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            self.fd = int(libc.inotify_init1(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)))
            if self.fd < 0:
                self.fd = -1
                return
            self._libc = libc
            for path in paths:
                directory = path if path.is_dir() else path.parent
                if directory.exists():
                    self._register_tree(directory)
        except (OSError, AttributeError):
            self.close()

    def _add_watch(self, directory: Path) -> None:
        if self.fd < 0 or not directory.is_dir():
            return
        try:
            wd = int(self._libc.inotify_add_watch(self.fd, os.fsencode(str(directory)), self.MASK))
        except OSError:
            return
        if wd >= 0:
            self.watches[wd] = directory

    def _register_tree(self, root: Path) -> None:
        self._add_watch(root)
        try:
            for directory, subdirs, _files in os.walk(root):
                # Do not follow symlinked directories: they can escape the
                # requested watch root or create an unbounded traversal.
                subdirs[:] = [name for name in subdirs if not (Path(directory) / name).is_symlink()]
                for name in subdirs:
                    self._add_watch(Path(directory) / name)
        except OSError:
            return

    def poll(self, timeout: float = 0.0) -> list[FileChangeRecord]:
        if self.fd < 0:
            return []
        ready, _, _ = select.select([self.fd], [], [], max(0.0, timeout))
        if not ready:
            return []
        try:
            data = os.read(self.fd, 1024 * 1024)
        except BlockingIOError:
            return []
        events: list[FileChangeRecord] = []
        offset = 0
        while offset + 16 <= len(data):
            wd, mask, _, length = struct.unpack_from("iIII", data, offset)
            offset += 16
            raw_name = data[offset:offset + length].split(b"\0", 1)[0]
            offset += length
            directory = self.watches.get(wd)
            if directory is None:
                continue
            name = os.fsdecode(raw_name)
            path = directory / name if name else directory
            is_directory = bool(mask & self.IN_ISDIR)
            if mask & self.IN_IGNORED:
                self.watches.pop(wd, None)
                continue
            # New directories do not inherit a parent's watch. Register them
            # immediately after emitting the create/move event.
            if is_directory and mask & (0x00000100 | 0x00000080):
                self._register_tree(path)
            if path.name in INTERNAL_EVIDENCE_NAMES:
                continue
            action = "modify"
            if mask & 0x00000100: action = "create"
            elif mask & 0x00000200: action = "delete"
            elif mask & 0x00000040: action = "rename_from"
            elif mask & 0x00000080: action = "rename_to"
            events.append(FileChangeRecord(str(path), action, "linux-inotify", utc_now(), is_directory))
        return events

    def close(self) -> None:
        if self.fd >= 0:
            try: os.close(self.fd)
            except OSError: pass
            self.fd = -1


class PollingFileWatcher:
    """Portable fallback; Windows can replace this with ETW when available."""

    def __init__(self, paths: Iterable[Path]):
        self.paths = [Path(path).expanduser() for path in paths]
        self.state: dict[str, tuple[int, int]] = {}
        self._prime()

    def _files(self) -> Iterable[Path]:
        for root in self.paths:
            if root.is_file():
                yield root
            elif root.is_dir():
                try:
                    yield from (item for item in root.rglob("*") if item.is_file() and item.name not in INTERNAL_EVIDENCE_NAMES)
                except OSError:
                    continue

    @staticmethod
    def _signature(path: Path) -> tuple[int, int]:
        try:
            stat = path.stat()
            return (int(stat.st_mtime_ns), int(stat.st_size))
        except OSError:
            return (0, 0)

    def _prime(self) -> None:
        self.state = {str(path): self._signature(path) for path in self._files()}

    def poll(self) -> list[FileChangeRecord]:
        current = {str(path): self._signature(path) for path in self._files()}
        events: list[FileChangeRecord] = []
        for path in current.keys() - self.state.keys():
            events.append(FileChangeRecord(path, "create", "windows-polling", utc_now()))
        for path in self.state.keys() - current.keys():
            events.append(FileChangeRecord(path, "delete", "windows-polling", utc_now()))
        for path in current.keys() & self.state.keys():
            if current[path] != self.state[path]:
                events.append(FileChangeRecord(path, "modify", "windows-polling", utc_now()))
        self.state = current
        return events

    def close(self) -> None:
        return None


def create_file_watcher(paths: Iterable[Path]):
    return LinuxInotifyWatcher(paths) if platform.system().lower() == "linux" else PollingFileWatcher(paths)


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
        "database": str(data / "AgentReins" / "evidence.sqlite3"),
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
    system = platform.system().lower()
    capabilities = ["processExecution", "processLineage", "networkConnection", "sqliteEvidence", "agentSessionCorrelation", "toolCallCorrelation"]
    if system == "linux":
        capabilities.append("fileChangeInotify")
    elif system == "windows":
        # A standard-library collector cannot safely start a kernel ETW
        # session without changing the user's tracing policy. We expose the
        # actual release capability (polling) rather than claiming ETW data.
        capabilities.append("fileChangePolling")
    else:
        capabilities.append("fileChangePolling")
    return {
        "schemaVersion": SCHEMA_VERSION,
        "version": VERSION,
        "timestamp": utc_now(),
        "platform": system,
        "collector": "agentreins-portable",
        "capabilities": capabilities,
        "processes": [asdict(item) for item in procs],
        "connections": [asdict(item) for item in network()],
        "fileEvents": [],
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
    watch.add_argument("--database", type=Path, help="SQLite evidence database")
    watch.add_argument("--watch-path", action="append", type=Path, default=[], help="directory/file to monitor")
    args = parser.parse_args(argv)
    if args.command == "paths":
        print(json.dumps(platform_paths(), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.command == "snapshot":
        write_snapshot(snapshot(), None)
        return 0
    interval = max(0.25, args.interval)
    paths = platform_paths()
    database = args.database or Path(paths["database"])
    store = EvidenceStore(database)
    watch_paths = args.watch_path or [Path(paths["data"])]
    file_watcher = create_file_watcher(watch_paths)
    web_reader = WebEvidenceReader(Path(paths["webEvidence"]))
    try:
        while True:
            started = time.monotonic()
            record = snapshot()
            file_events = file_watcher.poll()
            web_events = web_reader.poll()
            record["fileEvents"] = [asdict(event) for event in file_events]
            record["webEvents"] = web_events
            write_snapshot(record, args.output)
            store.append_web_events(web_events)
            store.append_snapshot(record)
            store.append_file_events(file_events, store.latest_context())
            time.sleep(max(0, interval - (time.monotonic() - started)))
    except KeyboardInterrupt:
        return 0
    finally:
        store.close()
        file_watcher.close()


if __name__ == "__main__":
    raise SystemExit(main())
