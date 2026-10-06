"""Cross-platform trace, verify and recover support for AgentReins.

The Swift client keeps a small, self-contained journal for every agent turn.
This module mirrors that contract without depending on a particular desktop UI
or operating system.  All external commands are argv based and bounded by a
timeout; callers can therefore safely use it from a polling thread.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


MAX_CAPTURE = 64_000
MAX_FILES = 400
MAX_FINGERPRINT_BYTES = 1_048_576


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return value


def _dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if value:
        raw = str(value).replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(raw)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return _now()


@dataclass(frozen=True)
class GitFileState:
    path: str
    status: str
    content_fingerprint: str | None = None
    original_path: str | None = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "GitFileState":
        return cls(str(value.get("path", "")), str(value.get("status", "")), value.get("contentFingerprint", value.get("content_fingerprint")), value.get("originalPath", value.get("original_path")))

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "status": self.status, "contentFingerprint": self.content_fingerprint, "originalPath": self.original_path}


@dataclass
class GitSnapshot:
    captured_at: datetime
    repository_root: str
    head: str | None
    porcelain_v2: str
    patch: str
    staged_patch: str
    diff_stat: str
    num_stat: str
    files: list[GitFileState] = field(default_factory=list)
    complete: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "capturedAt": _iso(self.captured_at), "repositoryRoot": self.repository_root,
            "head": self.head, "porcelainV2": self.porcelain_v2, "patch": self.patch,
            "stagedPatch": self.staged_patch, "diffStat": self.diff_stat, "numStat": self.num_stat,
            "files": [item.to_dict() for item in self.files], "complete": self.complete,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "GitSnapshot":
        return cls(_dt(value.get("capturedAt", value.get("captured_at"))), str(value.get("repositoryRoot", value.get("repository_root", ""))), value.get("head"), str(value.get("porcelainV2", value.get("porcelain_v2", ""))), str(value.get("patch", "")), str(value.get("stagedPatch", value.get("staged_patch", ""))), str(value.get("diffStat", value.get("diff_stat", ""))), str(value.get("numStat", value.get("num_stat", ""))), [GitFileState.from_dict(item) for item in value.get("files", [])], bool(value.get("complete", False)))


@dataclass
class FileMutation:
    path: str
    baseline_status: str | None
    final_status: str | None
    attribution: str
    evidence: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "path": self.path, "baselineStatus": self.baseline_status, "finalStatus": self.final_status, "attribution": self.attribution, "evidence": self.evidence}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FileMutation":
        return cls(str(value.get("path", "")), value.get("baselineStatus", value.get("baseline_status")), value.get("finalStatus", value.get("final_status")), str(value.get("attribution", "unknown")), str(value.get("evidence", "")), str(value.get("id", uuid.uuid4())))


@dataclass
class VerificationRun:
    command: str
    started_at: datetime
    duration: float
    exit_code: int
    standard_output: str = ""
    standard_error: str = ""
    tests_passed: int | None = None
    tests_failed: int | None = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "command": self.command, "startedAt": _iso(self.started_at), "duration": self.duration, "exitCode": self.exit_code, "standardOutput": self.standard_output, "standardError": self.standard_error, "testsPassed": self.tests_passed, "testsFailed": self.tests_failed}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerificationRun":
        return cls(str(value.get("command", "")), _dt(value.get("startedAt", value.get("started_at"))), float(value.get("duration", 0)), int(value.get("exitCode", value.get("exit_code", -1))), str(value.get("standardOutput", value.get("standard_output", ""))), str(value.get("standardError", value.get("standard_error", ""))), value.get("testsPassed", value.get("tests_passed")), value.get("testsFailed", value.get("tests_failed")), str(value.get("id", uuid.uuid4())))


@dataclass
class AgentTurnJournal:
    id: str
    session_id: str
    turn_id: str
    agent: str
    workspace: str | None
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "thinking"
    capture_complete: bool = False
    baseline_precedes_mutation: bool | None = None
    baseline: GitSnapshot | None = None
    final_snapshot: GitSnapshot | None = None
    mutations: list[FileMutation] = field(default_factory=list)
    verification_runs: list[VerificationRun] = field(default_factory=list)
    tool_call_ids: list[str] = field(default_factory=list)
    prompt: str = ""

    @property
    def has_pre_existing_changes(self) -> bool:
        return bool(self.baseline and self.baseline.files)

    @property
    def can_recover_safely(self) -> bool:
        return bool(self.baseline and self.final_snapshot and self.baseline.complete and self.final_snapshot.complete and not self.baseline.files and self.baseline.head and self.baseline.head == self.final_snapshot.head and self.mutations and self.baseline_precedes_mutation is True and self.status in {"completed", "failed", "cancelled", "stuck"} and all(item.content_fingerprint is not None for item in self.final_snapshot.files))

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "sessionId": self.session_id, "turnId": self.turn_id, "agent": self.agent, "workspace": self.workspace, "startedAt": _iso(self.started_at), "completedAt": _iso(self.completed_at), "status": self.status, "captureComplete": self.capture_complete, "baselinePrecedesMutation": self.baseline_precedes_mutation, "baseline": self.baseline.to_dict() if self.baseline else None, "finalSnapshot": self.final_snapshot.to_dict() if self.final_snapshot else None, "mutations": [item.to_dict() for item in self.mutations], "verificationRuns": [item.to_dict() for item in self.verification_runs], "toolCallIds": self.tool_call_ids, "prompt": self.prompt, "canRecoverSafely": self.can_recover_safely, "hasPreExistingChanges": self.has_pre_existing_changes}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AgentTurnJournal":
        return cls(str(value.get("id", "")), str(value.get("sessionId", value.get("session_id", ""))), str(value.get("turnId", value.get("turn_id", ""))), str(value.get("agent", "Agent")), value.get("workspace"), _dt(value.get("startedAt", value.get("started_at"))), _dt(value["completedAt"]) if value.get("completedAt") else None, str(value.get("status", "thinking")), bool(value.get("captureComplete", value.get("capture_complete", False))), value.get("baselinePrecedesMutation", value.get("baseline_precedes_mutation")), GitSnapshot.from_dict(value["baseline"]) if value.get("baseline") else None, GitSnapshot.from_dict(value["finalSnapshot"]) if value.get("finalSnapshot") else None, [FileMutation.from_dict(item) for item in value.get("mutations", [])], [VerificationRun.from_dict(item) for item in value.get("verificationRuns", [])], [str(item) for item in value.get("toolCallIds", [])], str(value.get("prompt", "")))


def _run(argv: Sequence[str], cwd: str | Path | None = None, timeout: float = 4.0, max_output: int = MAX_CAPTURE) -> tuple[int, str, str, bool, bool]:
    """Run with bounded memory/time; return code, stdout, stderr, timeout, truncation.

    Both pipes are drained concurrently so a verbose build cannot deadlock. Only
    their bounded tails remain in memory. A new process group lets a timeout
    terminate test runners and their child processes together.
    """
    buffers = [bytearray(), bytearray()]
    truncated = [False, False]
    def drain(stream: Any, index: int) -> None:
        try:
            for chunk in iter(lambda: stream.read(16_384), b""):
                buffers[index].extend(chunk)
                if len(buffers[index]) > max_output:
                    del buffers[index][:-max_output]
                    truncated[index] = True
        finally:
            stream.close()
    try:
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        process = subprocess.Popen(list(argv), cwd=str(cwd) if cwd else None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, creationflags=flags, start_new_session=os.name != "nt")
    except OSError as exc:
        return -1, "", str(exc), False, False
    readers = [threading.Thread(target=drain, args=(stream, index), daemon=True) for index, stream in enumerate((process.stdout, process.stderr))]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        process.wait(timeout=max(0.1, timeout))
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "nt":
            try:
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    for reader in readers:
        reader.join(timeout=1)
    # A detached child can retain a pipe: never wait indefinitely for it.
    output = [bytes(buffer).decode("utf-8", "replace") for buffer in buffers]
    return -1 if timed_out else process.returncode, output[0], output[1], timed_out, any(truncated)


class GitRepositoryInspector:
    @staticmethod
    def _git(args: Sequence[str], cwd: str | Path, timeout: float = 4.0) -> str | None:
        code, out, _, timed_out, truncated = _run(["git", *args], cwd=cwd, timeout=timeout)
        return out.strip() if code == 0 and not timed_out and not truncated else None

    @staticmethod
    def repository_root(workspace: str | Path) -> Path | None:
        root = GitRepositoryInspector._git(["rev-parse", "--show-toplevel"], workspace)
        return Path(root).resolve() if root else None

    @staticmethod
    def parse_porcelain(data: bytes | str) -> list[GitFileState]:
        text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
        records = [item for item in text.split("\0") if item]
        result: list[GitFileState] = []
        index = 0
        while index < len(records):
            record = records[index]
            if len(record) < 4:
                index += 1
                continue
            status, path = record[:2], record[3:]
            original_path = None
            if "R" in status or "C" in status:
                index += 1  # v1 -z follows with the old path
                original_path = records[index] if index < len(records) else None
            result.append(GitFileState(path, status, original_path=original_path))
            index += 1
        return sorted(result, key=lambda item: item.path)

    @staticmethod
    def _fingerprint(root: Path, path: str) -> str | None:
        try:
            candidate = root / path
            parent = candidate.parent.resolve()
            if os.path.commonpath([str(root), str(parent)]) != str(root):
                return None
            if candidate.is_symlink():
                return "symlink:" + hashlib.sha256(os.fsencode(os.readlink(candidate))).hexdigest()
            if not candidate.exists():
                return "absent"
            if not candidate.is_file() or candidate.stat().st_size > MAX_FINGERPRINT_BYTES:
                return None
            digest = hashlib.sha256()
            with candidate.open("rb") as stream:
                for block in iter(lambda: stream.read(64 * 1024), b""):
                    digest.update(block)
            return digest.hexdigest()
        except (OSError, ValueError):
            return None

    @classmethod
    def capture(cls, workspace: str | Path, at: datetime | None = None, timeout: float = 4.0) -> GitSnapshot | None:
        root = cls.repository_root(workspace)
        if root is None:
            return None
        def text(args: Sequence[str]) -> str:
            return cls._git(args, root, timeout) or ""
        raw_code, raw, _, _, raw_truncated = _run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=root, timeout=timeout, max_output=4_194_304)
        if raw_code != 0 or raw_truncated:
            return None
        files = cls.parse_porcelain(raw)
        complete = len(files) <= MAX_FILES
        files = [GitFileState(item.path, item.status, cls._fingerprint(root, item.path), item.original_path) for item in files[:MAX_FILES]]
        return GitSnapshot(at or _now(), str(root), text(["rev-parse", "HEAD"]) or None, text(["status", "--porcelain=v2", "--untracked-files=all"]), text(["diff", "--no-ext-diff", "--no-textconv"]), text(["diff", "--cached", "--no-ext-diff", "--no-textconv"]), text(["diff", "--stat", "--no-ext-diff", "--no-textconv", "HEAD"]), text(["diff", "--numstat", "--no-ext-diff", "--no-textconv", "HEAD"]), files, complete)

    @staticmethod
    def mutations(baseline: GitSnapshot | None, final: GitSnapshot | None, baseline_precedes_mutation: bool | None = None) -> list[FileMutation]:
        if final is None:
            return []
        before = {item.path: item for item in (baseline.files if baseline else [])}
        after = {item.path: item for item in final.files}
        confidence = "inferred" if baseline is not None and baseline_precedes_mutation is True else "unknown"
        evidence = "The file content or Git state changed after the prompt baseline; attribution is temporal, not hook-confirmed." if confidence == "inferred" else ("No pre-turn Git baseline was captured." if baseline is None else "A Git baseline exists, but AgentReins cannot prove it preceded the first mutation.")
        result = []
        for path in sorted(set(before) | set(after)):
            old, new = before.get(path), after.get(path)
            if old == new:
                continue
            result.append(FileMutation(path, old.status if old else None, new.status if new else None, confidence, evidence))
        return result


@dataclass(frozen=True)
class VerificationCommand:
    executable: str
    arguments: tuple[str, ...]
    display_name: str

    @property
    def argv(self) -> list[str]:
        return [self.executable, *self.arguments]


class ProjectVerifier:
    @staticmethod
    def commands(workspace: str | Path) -> list[VerificationCommand]:
        root = Path(workspace)
        if (root / "Package.swift").exists():
            commands = [VerificationCommand(shutil.which("swift") or "swift", ("build",), "swift build")]
            if (root / "Tests").exists():
                commands.append(VerificationCommand(shutil.which("swift") or "swift", ("test",), "swift test"))
            return commands
        if (root / "package.json").exists():
            try:
                scripts = json.loads((root / "package.json").read_text(encoding="utf-8")).get("scripts", {})
            except (OSError, ValueError):
                scripts = {}
            manager = "pnpm" if (root / "pnpm-lock.yaml").exists() else "yarn" if (root / "yarn.lock").exists() else "npm"
            return [VerificationCommand(shutil.which(manager) or manager, ("run", name), f"{manager} run {name}") for name in ("build", "test") if name in scripts]
        if any((root / name).exists() for name in ("pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini")):
            python = shutil.which("python") or shutil.which("python3") or "python"
            return [VerificationCommand(python, ("-m", "pytest"), f"{Path(python).name} -m pytest")]
        if (root / "go.mod").exists():
            return [VerificationCommand(shutil.which("go") or "go", ("test", "./..."), "go test ./...")]
        if (root / "Cargo.toml").exists():
            return [VerificationCommand(shutil.which("cargo") or "cargo", ("test",), "cargo test")]
        return []

    @staticmethod
    def run(command: VerificationCommand, workspace: str | Path, timeout: float = 300.0) -> VerificationRun:
        started = _now()
        start = time.monotonic()
        code, out, err, timed_out, _ = _run(command.argv, cwd=workspace, timeout=timeout)
        if timed_out:
            err = (err + "\nVerification timed out after %d seconds." % int(timeout)).strip()
        return VerificationRun(command.display_name, started, time.monotonic() - start, code, out[-MAX_CAPTURE:], err[-MAX_CAPTURE:])


@dataclass(frozen=True)
class RecoveryResult:
    success: bool
    message: str


class GitRecovery:
    @staticmethod
    def _safe_path(root: Path, raw_path: str) -> Path:
        relative = Path(raw_path)
        if not raw_path or relative.is_absolute() or relative.drive or ".." in relative.parts or ".git" in (part.lower() for part in relative.parts):
            raise ValueError("Path escaped the repository or targets Git metadata")
        candidate = root / relative
        parent = candidate.parent.resolve()
        if os.path.commonpath([str(root), str(parent)]) != str(root):
            raise ValueError("Path parent escaped the repository")
        # Junctions/reparse points cannot be traversed by recovery.
        cursor = candidate.parent
        while cursor != root:
            if cursor.is_symlink() or (hasattr(cursor, "is_junction") and cursor.is_junction()):
                raise ValueError("Path traverses a link")
            cursor = cursor.parent
        if candidate.is_dir() and not candidate.is_symlink():
            raise ValueError("Directory/submodule recovery is unsupported")
        return candidate

    @staticmethod
    def restore_clean_baseline(workspace: str | Path, head: str, untracked_paths: Iterable[str], expected_final: GitSnapshot | None = None) -> RecoveryResult:
        root = GitRepositoryInspector.repository_root(workspace)
        if root is None:
            return RecoveryResult(False, "Recovery failed because the Git repository is unavailable.")
        if expected_final is None or not expected_final.complete or head != expected_final.head:
            return RecoveryResult(False, "Recovery requires a complete recorded final snapshot with unchanged HEAD.")
        current = GitRepositoryInspector.capture(root)
        if current is None or not current.complete or current.repository_root != expected_final.repository_root or current.head != expected_final.head or current.porcelain_v2 != expected_final.porcelain_v2 or current.files != expected_final.files or any(item.content_fingerprint is None for item in current.files):
            return RecoveryResult(False, "Recovery was blocked because the workspace changed after the recorded turn or contains unverifiable files.")
        expected_untracked = {item.path for item in expected_final.files if item.status == "??"}
        if set(untracked_paths) != expected_untracked:
            return RecoveryResult(False, "Recovery paths do not match the recorded untracked files.")
        tracked: set[str] = set()
        try:
            for item in expected_final.files:
                GitRecovery._safe_path(root, item.path)
                if item.status != "??":
                    tracked.add(item.path)
                    if item.original_path:
                        GitRecovery._safe_path(root, item.original_path)
                        tracked.add(item.original_path)
        except (OSError, ValueError) as exc:
            return RecoveryResult(False, f"Recovery stopped before changing files: {exc}.")
        # Restore only reviewed paths. Never reset HEAD, clean the repository,
        # recurse into directories or discard unrelated files.
        if tracked:
            code, _, err, _, _ = _run(["git", "--literal-pathspecs", "restore", f"--source={head}", "--staged", "--worktree", "--", *sorted(tracked)], cwd=root, timeout=30)
            if code != 0:
                return RecoveryResult(False, "Git could not restore the tracked files." + (f" {err.strip()}" if err else ""))
        for raw_path in sorted(expected_untracked):
            try:
                candidate = GitRecovery._safe_path(root, raw_path)
                recorded = next(item for item in expected_final.files if item.path == raw_path)
                if GitRepositoryInspector._fingerprint(root, raw_path) != recorded.content_fingerprint:
                    return RecoveryResult(False, f"Recovery stopped because {raw_path} changed during recovery.")
                if candidate.exists() or candidate.is_symlink():
                    candidate.unlink()
            except (OSError, ValueError) as exc:
                return RecoveryResult(False, f"Recovery could not remove {raw_path}: {exc}")
        check = GitRepositoryInspector.capture(root)
        if check is None or check.head != head or check.files:
            return RecoveryResult(False, "Recovery completed but the clean baseline could not be verified.")
        return RecoveryResult(True, "The clean Git baseline was restored and verified.")


class JournalPersistence:
    """Small persistence adapter usable with the existing EvidenceStore connection."""
    SCHEMA = """CREATE TABLE IF NOT EXISTS agent_turn_journals (journal_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, turn_id TEXT NOT NULL, started_at TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL, updated_at TEXT NOT NULL)"""

    @classmethod
    def ensure_sqlite(cls, connection: sqlite3.Connection) -> None:
        connection.execute(cls.SCHEMA)
        connection.execute("CREATE INDEX IF NOT EXISTS agent_turn_journals_session ON agent_turn_journals(session_id, started_at DESC)")
        connection.commit()

    @classmethod
    def save_sqlite(cls, connection: sqlite3.Connection, journal: AgentTurnJournal) -> None:
        cls.ensure_sqlite(connection)
        now = _iso(_now())
        connection.execute("INSERT INTO agent_turn_journals(journal_id,session_id,turn_id,started_at,status,payload,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(journal_id) DO UPDATE SET status=excluded.status,payload=excluded.payload,updated_at=excluded.updated_at", (journal.id, journal.session_id, journal.turn_id, _iso(journal.started_at), journal.status, json.dumps(journal.to_dict(), ensure_ascii=False, sort_keys=True), now))
        connection.commit()

    @classmethod
    def load_sqlite(cls, connection: sqlite3.Connection, journal_id: str) -> AgentTurnJournal | None:
        cls.ensure_sqlite(connection)
        row = connection.execute("SELECT payload FROM agent_turn_journals WHERE journal_id=?", (journal_id,)).fetchone()
        return AgentTurnJournal.from_dict(json.loads(row[0])) if row else None

    @staticmethod
    def save_json(path: str | Path, journals: Iterable[AgentTurnJournal]) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schemaVersion": 1, "journals": [item.to_dict() for item in journals]}
        temporary = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent, delete=False) as stream:
                temporary = Path(stream.name)
                json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

    @staticmethod
    def load_json(path: str | Path) -> list[AgentTurnJournal]:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            values = payload.get("journals", payload) if isinstance(payload, dict) else payload
            return [AgentTurnJournal.from_dict(item) for item in values]
        except (OSError, ValueError, TypeError, AttributeError):
            return []


class TurnJournalStore:
    """Synchronous service; call capture/verify/recover from a background worker.

    ``begin`` is the deliberate, pre-task checkpoint. Transcript ``ingest``
    never claims that a snapshot taken after reading a prompt predates edits.
    Verification and recovery only run through explicit methods.
    """

    def __init__(self, path: str | Path | None = None, database: str | Path | sqlite3.Connection | None = None, max_journals: int = 100, load: bool = True):
        self.path = Path(path) if path else None
        self.database = database
        self.max_journals = max(1, max_journals)
        self._lock = threading.RLock()
        self._journals: dict[str, AgentTurnJournal] = {}
        self._seen_events: set[str] = set()
        self.verification_states: dict[str, str] = {}
        self.recovery_messages: dict[str, str] = {}
        if load:
            initial = JournalPersistence.load_json(self.path) if self.path else []
            if not initial and database is not None:
                connection, owned = self._connection()
                try:
                    JournalPersistence.ensure_sqlite(connection)
                    rows = connection.execute("SELECT payload FROM agent_turn_journals ORDER BY started_at DESC LIMIT ?", (self.max_journals,)).fetchall()
                    initial = [AgentTurnJournal.from_dict(json.loads(row[0])) for row in rows]
                finally:
                    if owned:
                        connection.close()
            self._journals = {item.id: item for item in initial[:self.max_journals]}
            for journal in self._journals.values():
                if journal.verification_runs:
                    self.verification_states[journal.id] = "passed" if journal.verification_runs[-1].succeeded else "failed"

    def _connection(self) -> tuple[sqlite3.Connection, bool]:
        if isinstance(self.database, sqlite3.Connection):
            return self.database, False
        if self.database is None:
            raise ValueError("No database configured")
        path = Path(self.database)
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(path), timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection, True

    @staticmethod
    def journal_id(session_id: str, turn_id: str) -> str:
        # Length-prefixing prevents ambiguities when provider IDs contain colons.
        return f"{len(session_id)}:{session_id}:{turn_id}"

    @property
    def journals(self) -> list[AgentTurnJournal]:
        return self.list()

    def list(self, session_id: str | None = None) -> list[AgentTurnJournal]:
        with self._lock:
            return sorted((item for item in self._journals.values() if session_id is None or item.session_id == session_id), key=lambda item: item.started_at, reverse=True)

    def get(self, journal_id: str) -> AgentTurnJournal | None:
        with self._lock:
            return self._journals.get(journal_id)

    def snapshot(self) -> dict[str, Any]:
        """Return detached JSON values under the journal lock for UI readers."""
        with self._lock:
            return {"journals": [item.to_dict() for item in self.list()],
                    "verificationStates": dict(self.verification_states),
                    "recoveryMessages": dict(self.recovery_messages)}

    def _require(self, journal_id: str) -> AgentTurnJournal:
        journal = self.get(journal_id)
        if journal is None:
            raise KeyError(f"Unknown turn journal: {journal_id}")
        return journal

    def _save(self, journal: AgentTurnJournal) -> None:
        latest = self.list()[:self.max_journals]
        self._journals = {item.id: item for item in latest}
        if self.path:
            JournalPersistence.save_json(self.path, latest)
        if self.database is not None:
            connection, owned = self._connection()
            try:
                JournalPersistence.save_sqlite(connection, journal)
            finally:
                if owned:
                    connection.close()

    def begin(self, workspace: str | Path, session_id: str | None = None, turn_id: str | None = None, agent: str = "manual", prompt: str = "") -> AgentTurnJournal:
        with self._lock:
            session_id = session_id or f"manual-{uuid.uuid4()}"
            turn_id = turn_id or str(uuid.uuid4())
            identity = self.journal_id(session_id, turn_id)
            if identity in self._journals:
                raise ValueError("This turn already has a journal; its baseline cannot be replaced")
            root = Path(workspace).expanduser().resolve()
            if not root.is_dir():
                raise ValueError("Workspace must be an existing directory")
            baseline = GitRepositoryInspector.capture(root)
            journal = AgentTurnJournal(identity, session_id, turn_id, agent, str(root), _now(), capture_complete=baseline is not None, baseline_precedes_mutation=baseline is not None, baseline=baseline, prompt=prompt[:MAX_CAPTURE])
            self._journals[identity] = journal
            self._save(journal)
            return journal

    def finish(self, journal_id: str, status: str = "completed") -> AgentTurnJournal:
        if status not in {"completed", "failed", "cancelled", "stuck"}:
            raise ValueError("Final status must be completed, failed, cancelled or stuck")
        with self._lock:
            journal = self._require(journal_id)
            if journal.completed_at is not None:
                return journal
            journal.completed_at = _now()
            journal.status = status
            journal.final_snapshot = GitRepositoryInspector.capture(journal.workspace) if journal.workspace else None
            journal.mutations = GitRepositoryInspector.mutations(journal.baseline, journal.final_snapshot, journal.baseline_precedes_mutation)
            self._save(journal)
            return journal

    def ingest(self, events: Iterable[Mapping[str, Any]]) -> list[AgentTurnJournal]:
        touched: dict[str, AgentTurnJournal] = {}
        with self._lock:
            for event in sorted(events, key=lambda item: _dt(item.get("timestamp", item.get("ts")))):
                event_id = str(event.get("eventId") or event.get("id") or "")
                if event_id and event_id in self._seen_events:
                    continue
                session = str(event.get("sessionId") or event.get("session_id") or "")
                turn = str(event.get("turnId") or event.get("turn_id") or "")
                if not session or not turn:
                    continue
                if event_id:
                    self._seen_events.add(event_id)
                identity = self.journal_id(session, turn)
                journal = self._journals.get(identity)
                kind = str(event.get("eventType") or event.get("op") or "")
                action = str(event.get("action") or "").lower()
                metadata = event.get("metadata") if isinstance(event.get("metadata"), Mapping) else {}
                candidate = event.get("workspace") or metadata.get("workspace") or metadata.get("cwd") or event.get("cwd") or event.get("path")
                workspace = None
                if candidate and str(candidate) != "-":
                    path = Path(str(candidate)).expanduser()
                    if path.is_dir():
                        workspace = str(path.resolve())
                if journal is None:
                    journal = AgentTurnJournal(identity, session, turn, str(event.get("provider") or event.get("agent") or "Agent"), workspace, _dt(event.get("timestamp", event.get("ts"))), capture_complete=False, baseline_precedes_mutation=False)
                    self._journals[identity] = journal
                if journal.workspace is None and workspace:
                    journal.workspace = workspace
                if kind == "prompt" and not journal.prompt:
                    journal.prompt = str(event.get("text") or event.get("userIntent") or "")[:MAX_CAPTURE]
                call_id = event.get("toolCallId") or event.get("tool_call_id")
                if call_id and str(call_id) not in journal.tool_call_ids:
                    journal.tool_call_ids.append(str(call_id))
                if journal.completed_at is None:
                    if action in {"failed", "error", "cancelled"}:
                        self.finish(identity, "failed" if action in {"failed", "error"} else "cancelled")
                        journal.completed_at = _dt(event.get("timestamp", event.get("ts")))
                    elif kind == "response" and action not in {"commentary", "intermediate", "analysis"} and metadata.get("phase") not in {"commentary", "analysis"}:
                        self.finish(identity)
                        journal.completed_at = _dt(event.get("timestamp", event.get("ts")))
                    else:
                        journal.status = "running" if kind in {"tool_call", "call"} else "thinking"
                touched[identity] = journal
            for journal in touched.values():
                self._save(journal)
            if len(self._seen_events) > 10_000:
                self._seen_events = set(list(self._seen_events)[-5_000:])
        return list(touched.values())

    def verification_commands(self, journal_id: str) -> list[VerificationCommand]:
        journal = self._require(journal_id)
        return ProjectVerifier.commands(journal.workspace) if journal.workspace else []

    def verify(self, journal_id: str, commands: Sequence[VerificationCommand] | None = None, timeout: float = 300.0) -> list[VerificationRun]:
        with self._lock:
            journal = self._require(journal_id)
            if not journal.workspace:
                raise ValueError("This journal has no local workspace")
            if self.verification_states.get(journal_id) == "running":
                raise ValueError("Verification is already running")
            commands = list(commands) if commands is not None else self.verification_commands(journal_id)
            if not commands:
                raise ValueError("No supported verification command was detected")
            self.verification_states[journal_id] = "running"
        runs = []
        try:
            for command in commands:
                run = ProjectVerifier.run(command, journal.workspace, timeout)
                runs.append(run)
                if run.exit_code:
                    break
        finally:
            with self._lock:
                journal.verification_runs.extend(runs)
                self.verification_states[journal_id] = "passed" if runs and all(item.succeeded for item in runs) else "failed"
                self._save(journal)
        return runs

    def preview_recovery(self, journal_id: str) -> dict[str, Any]:
        journal = self._require(journal_id)
        reason = ""
        if not journal.baseline_precedes_mutation:
            reason = "No verified pre-task baseline exists. Start a checkpoint before the next task."
        elif journal.has_pre_existing_changes:
            reason = "The baseline contains pre-existing user changes. Automatic recovery is unavailable."
        elif not journal.can_recover_safely:
            reason = "Recovery requires a completed turn, unchanged HEAD, a complete clean baseline and verifiable file changes."
        elif self.verification_states.get(journal_id) == "running":
            reason = "Wait for verification to finish before recovery."
        else:
            current = GitRepositoryInspector.capture(journal.workspace) if journal.workspace else None
            final = journal.final_snapshot
            if current is None or not current.complete or final is None or current.repository_root != final.repository_root or current.head != final.head or current.porcelain_v2 != final.porcelain_v2 or current.files != final.files:
                reason = "The workspace changed after the recorded turn. Recovery would overwrite later work."
            elif final:
                try:
                    root = Path(final.repository_root)
                    for item in final.files:
                        GitRecovery._safe_path(root, item.path)
                        if item.original_path:
                            GitRecovery._safe_path(root, item.original_path)
                except (OSError, ValueError) as exc:
                    reason = str(exc)
        files = journal.final_snapshot.files if journal.final_snapshot else []
        return {"journalId": journal.id, "allowed": not reason, "reason": reason, "restorePaths": sorted({path for item in files if item.status != "??" for path in (item.path, item.original_path) if path}), "removePaths": sorted(item.path for item in files if item.status == "??"), "head": journal.baseline.head if journal.baseline else None}

    def recover(self, journal_id: str) -> RecoveryResult:
        with self._lock:
            journal = self._require(journal_id)
            preview = self.preview_recovery(journal_id)
            if not preview["allowed"]:
                result = RecoveryResult(False, preview["reason"])
            else:
                result = GitRecovery.restore_clean_baseline(journal.workspace or "", preview["head"], preview["removePaths"], journal.final_snapshot)
            self.recovery_messages[journal_id] = result.message
            # Retain the recorded final snapshot and mutation evidence for audit.
            self._save(journal)
            return result


# Names useful to callers porting UI logic.
GitRepositoryInspector.capture_snapshot = GitRepositoryInspector.capture
ProjectVerifier.detect_commands = ProjectVerifier.commands
GitRecovery.restoreCleanBaseline = GitRecovery.restore_clean_baseline

