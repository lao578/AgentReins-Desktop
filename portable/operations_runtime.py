"""Shared operations service for desktop and headless collection."""
from __future__ import annotations

import copy
import json
import sqlite3
import threading
from contextlib import closing
from pathlib import Path
from typing import Any

try:
    from evidence_projection import EvidenceProjector
    from turn_journal import TurnJournalStore, VerificationCommand
    from safety_features import FileProtectionStore, MemoryAuditor, SemanticAnalyzer, summarize_security
except ImportError:
    from .evidence_projection import EvidenceProjector
    from .turn_journal import TurnJournalStore, VerificationCommand
    from .safety_features import FileProtectionStore, MemoryAuditor, SemanticAnalyzer, summarize_security


class OperationsRuntime:
    """Thread-safe facade for UI and headless clients.

    Locks are deliberately scoped: collection never holds ``_lock`` while
    waiting on the journal, protection store or SQLite. Long operations are
    therefore safe to invoke from worker threads while ``view`` keeps serving.
    """
    def __init__(self, database: Path):
        self.database = Path(database).expanduser().resolve()
        self.state_dir = self.database.parent / (self.database.stem + "-operations")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.projector = EvidenceProjector(max_events=2500)
        self.journal = TurnJournalStore(database=self.database)
        self.protection = FileProtectionStore(self.state_dir)
        self.memory = MemoryAuditor(self.state_dir)
        self.analysis = SemanticAnalyzer(self.state_dir)
        self._lock = threading.RLock()
        self._history_lock = threading.Lock()
        self._memory_lock = threading.Lock()
        self._analysis_lock = threading.Lock()
        self._observe_lock = threading.Lock()
        self._last_record: dict[str, Any] = {}
        self._memory: dict[str, Any] = {"inventory": [], "findings": [], "errors": []}
        self._protection_events: list[dict[str, Any]] = []
        self._security: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._analyses: list[dict[str, Any]] = []
        self._history_loaded = False
        self._history_errors: list[str] = []

    def _state_write(self, key: str, value: Any) -> None:
        with closing(sqlite3.connect(str(self.database), timeout=10)) as connection:
            with connection:
                connection.execute("CREATE TABLE IF NOT EXISTS operations_state (name TEXT PRIMARY KEY,payload TEXT NOT NULL)")
                connection.execute("INSERT INTO operations_state VALUES(?,?) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload", (key, json.dumps(value, ensure_ascii=True)))

    def _load_history(self) -> None:
        with self._history_lock:
            if self._history_loaded:
                return
            events: list[dict[str, Any]] = []
            files: list[dict[str, Any]] = []
            latest: dict[str, Any] = {}
            saved: dict[str, Any] = {}
            errors: list[str] = []
            def decode(raw: str, table: str) -> Any:
                try:
                    return json.loads(raw)
                except (TypeError, ValueError):
                    errors.append(f"Skipped malformed JSON in {table}")
                    return None
            with closing(sqlite3.connect(str(self.database), timeout=10)) as connection:
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if "web_events" in tables:
                    for row in connection.execute("SELECT payload FROM web_events ORDER BY id DESC LIMIT 2000"):
                        value = decode(row[0], "web_events")
                        if isinstance(value, dict):
                            events.append(value)
                    events.reverse()
                if "file_events" in tables:
                    for row in connection.execute("SELECT id,timestamp,path,action,source,details FROM file_events ORDER BY id DESC LIMIT 500"):
                        details = decode(row[5] or "{}", "file_events")
                        files.append({"id": f"file-db-{row[0]}", "timestamp": row[1], "path": row[2], "action": row[3], "source": row[4], "details": details if isinstance(details, dict) else {}})
                    files.reverse()
                if "snapshots" in tables:
                    row = connection.execute("SELECT payload FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
                    value = decode(row[0], "snapshots") if row else None
                    if isinstance(value, dict):
                        latest = {key: value[key] for key in ("timestamp", "platform", "processes", "connections", "collectorHealth") if key in value}
                if "operations_state" in tables:
                    for name, payload in connection.execute("SELECT name,payload FROM operations_state"):
                        saved[name] = decode(payload, "operations_state")
            with self._lock:
                if not self._last_record:
                    self._last_record = latest
                self.projector.project({**latest, "nativeEvents": events, "fileEvents": files})
                self._assess(events)
                if isinstance(saved.get("memory"), dict):
                    self._memory = saved["memory"]
                if isinstance(saved.get("analyses"), list):
                    self._analyses = saved["analyses"][-100:]
                if isinstance(saved.get("protectionEvents"), list):
                    self._protection_events = saved["protectionEvents"][-300:]
                self._history_errors = errors[:50]
                self._history_loaded = True

    def _assess(self, events: list[dict[str, Any]]) -> None:
        for event in events:
            identity = str(event.get("eventId") or "")
            key = (str(event.get("provider") or ""), str(event.get("sessionId") or ""), identity)
            if not identity or key in self._security:
                continue
            result = summarize_security([event])
            for finding in result.get("codeFindings", []):
                finding.update(eventId=identity, sessionId=event.get("sessionId"), toolName=event.get("toolName"), confidence="review-suggestion")
            self._security[key] = result
        while len(self._security) > 2000:
            self._security.pop(next(iter(self._security)))

    def observe(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._observe_lock:
            self._load_history()
            events = [event for key in ("nativeEvents", "webEvents") for event in (record.get(key) or []) if isinstance(event, dict)]
            self.journal.ingest(events)
            protection_events = self.protection.check()
            with self._lock:
                self._assess(events)
                self._protection_events = (self._protection_events + protection_events)[-300:]
                self._last_record = copy.deepcopy({key: value for key, value in record.items() if key != "operations"})
                self.projector.project(self._last_record)
                saved_events = copy.deepcopy(self._protection_events)
            if protection_events:
                self._state_write("protectionEvents", saved_events)
        return self.view()

    def view(self) -> dict[str, Any]:
        self._load_history()
        journal_view = self.journal.snapshot()
        protected_files = self.protection.list_rules()
        with self._lock:
            projection = self.projector.project({})
            projection.update(journal_view)
            projection["protectedFiles"] = protected_files
            projection["protectionEvents"] = list(self._protection_events)
            projection["memory"] = copy.deepcopy(self._memory)
            projection["generatedCode"] = [finding for value in self._security.values() for finding in value.get("codeFindings", [])][-500:]
            projection["externalContent"] = [finding for value in self._security.values() for finding in value.get("externalContent", [])][-300:]
            projection["analyses"] = copy.deepcopy(self._analyses)
            projection["analysisConfiguration"] = dict(self.analysis.config)
            projection["collectorHealth"] = self._last_record.get("collectorHealth", {})
            projection["historyHealth"] = {"loaded": self._history_loaded, "errors": list(self._history_errors)}
            return copy.deepcopy(projection)

    @staticmethod
    def _commands(raw: Any) -> list[VerificationCommand] | None:
        if raw is None:
            return None
        commands = []
        for value in raw:
            if isinstance(value, VerificationCommand):
                commands.append(value)
                continue
            argv = value.get("command") if isinstance(value, dict) else value
            if not isinstance(argv, (list, tuple)) or not argv or any(not isinstance(item, str) or "\0" in item for item in argv):
                raise ValueError("Verification commands must be nonempty string argv lists")
            commands.append(VerificationCommand(argv[0], tuple(argv[1:]), str(value.get("name") or " ".join(argv)) if isinstance(value, dict) else " ".join(argv)))
        return commands

    def run_action(self, action: str, **arguments: Any) -> Any:
        if action in {"history", "report"}:
            self._load_history()
            return self.view()
        if action == "begin":
            return self.journal.begin(arguments["workspace"], session_id=arguments.get("session_id"), turn_id=arguments.get("turn_id"), agent=arguments.get("agent", "manual"), prompt=arguments.get("prompt", "")).to_dict()
        if action == "finish":
            return self.journal.finish(arguments["journal_id"], status=arguments.get("status", "completed")).to_dict()
        if action == "verification-preview":
            commands = self._commands(arguments.get("commands")) or self.journal.verification_commands(arguments["journal_id"])
            return [{"command": command.argv, "name": command.display_name} for command in commands]
        if action == "verify":
            return [run.to_dict() for run in self.journal.verify(arguments["journal_id"], commands=self._commands(arguments.get("commands")), timeout=float(arguments.get("timeout", 300)))]
        if action == "recovery-preview":
            return self.journal.preview_recovery(arguments["journal_id"])
        if action == "recover":
            result = self.journal.recover(arguments["journal_id"])
            return {"success": result.success, "message": result.message}
        if action == "protect":
            return self.protection.add_rule(Path(arguments["path"]), auto_restore=arguments.get("auto_restore", False))
        if action == "protection-list":
            return self.protection.list_rules()
        if action == "unprotect":
            self.protection.remove_rule(arguments["rule_id"])
            return {"removed": arguments["rule_id"]}
        if action == "restore-file":
            return self.protection.restore(arguments["rule_id"], expected_fingerprint=arguments["fingerprint"]) if "fingerprint" in arguments else self.protection.restore(arguments["rule_id"])
        if action == "scan-memory":
            self._load_history()
            targets = [Path(value) for value in arguments["targets"]] if arguments.get("targets") else None
            with self._memory_lock:
                result = self.memory.scan(targets=targets)
                with self._lock:
                    self._memory = result
                self._state_write("memory", result)
            return result
        if action == "redact-memory":
            with self._memory_lock:
                return self.memory.redact_finding(arguments["finding"])
        if action == "restore-memory":
            with self._memory_lock:
                return self.memory.restore(Path(arguments["path"]))
        if action == "configure-analysis":
            with self._analysis_lock:
                return self.analysis.configure(arguments["base_url"], arguments["model"], arguments.get("key_env", "AGENTREINS_ANALYSIS_API_KEY"))
        if action == "analyze":
            self._load_history()
            with self._analysis_lock:
                result = self.analysis.analyze(arguments["evidence"])
                with self._lock:
                    self._analyses = (self._analyses + [result])[-100:]
                    saved_analyses = copy.deepcopy(self._analyses)
                self._state_write("analyses", saved_analyses)
            return result
        raise ValueError("Unknown operations action: " + action)
