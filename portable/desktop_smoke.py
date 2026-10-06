#!/usr/bin/env python3
"""Deterministic Tk smoke check using synthetic evidence and isolated storage.

Windows: python portable/desktop_smoke.py
Linux:   xvfb-run -a python portable/desktop_smoke.py

No agent directories are read, no network calls are made, and the OS collectors
or tray integration are never started. Use this alongside backend unit tests;
it verifies construction, data binding, navigation, details and language changes.
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

try:
    import agentreins_desktop as desktop
    from evidence_projection import EvidenceProjector
except ImportError:
    from . import agentreins_desktop as desktop
    from .evidence_projection import EvidenceProjector


def main() -> int:
    errors = []
    with tempfile.TemporaryDirectory(prefix="agentreins-ui-smoke-") as directory:
        root = Path(directory)
        paths = {"data": str(root), "config": str(root / "config"), "cache": str(root / "cache"),
                 "evidence": str(root / "evidence.jsonl"), "database": str(root / "evidence.sqlite3"),
                 "webEvidence": str(root / "web-agent-events.jsonl")}
        record = {"schemaVersion": 2, "timestamp": "2026-01-01T00:00:00Z", "platform": "smoke",
                  "agents": [{"id": "codex", "instances": 1, "processIds": [111]}],
                  "processes": [{"pid": 111, "ppid": 1, "agent": "codex", "executable": "codex", "command": "codex"}],
                  "connections": [{"pid": 111, "local": "127.0.0.1:5000", "remote": "example.com:443", "protocol": "tcp", "state": "ESTABLISHED"}],
                  "fileEvents": [{"path": "C:/tmp/a.py", "action": "modify", "source": "smoke", "timestamp": "2026-01-01T00:00:01Z"}], "webEvents": [], "nativeEvents": [
                      {"eventId": "smoke-prompt", "eventType": "prompt", "provider": "codex", "sessionId": "smoke-session", "turnId": "smoke-turn", "timestamp": "2026-01-01T00:00:00Z", "text": "Verify the example"},
                      {"eventId": "smoke-tool", "eventType": "tool_call", "provider": "codex", "sessionId": "smoke-session", "turnId": "smoke-turn", "toolCallId": "smoke-call", "timestamp": "2026-01-01T00:00:01Z", "toolName": "shell_exec", "command": "echo hi"}],
                  "collectorHealth": {"status": "observed", "scope": "synthetic"}}
        view = EvidenceProjector().project(record)
        view.update({"journals": [{"id": "smoke-journal", "agent": "codex", "status": "running", "workspace": str(root), "prompt": "Verify the example", "verificationRuns": []}],
                     "verificationStates": {}, "protectedFiles": [], "protectionEvents": [],
                     "memory": {"inventory": [{"path": str(root / "memory.md"), "sensitiveCount": 1}],
                                "findings": [{"path": str(root / "memory.md"), "type": "OpenAI API Key", "severity": "high", "preview": "[REDACTED]"}], "errors": []},
                     "generatedCode": [],
                     "externalContent": [], "analyses": [], "collectorHealth": record["collectorHealth"]})
        view["evidenceIntegrity"] = {"status": "healthy", "count": 3, "head": "smoke-head", "errors": []}
        with patch.object(desktop, "platform_paths", return_value=paths), \
             patch.object(desktop.AgentReinsDesktop, "_prepare_optional_tray", return_value=None):
            app = desktop.AgentReinsDesktop()
            app.withdraw()
            app.report_callback_exception = lambda kind, value, trace: errors.append(f"{kind.__name__}: {value}")
            try:
                app._populate_record(record)
                app._populate_operations(view)
                assert getattr(app, "_journal_rows", []) and app._journal_rows[0]["id"] == "smoke-journal", f"Journal model was not populated: {getattr(app, '_journal_rows', None)}"
                app.update_idletasks()
                app.update()
                assert app.process_tree.get_children(), "Process evidence did not render"
                assert app.network_tree.get_children(), "Network evidence did not render"
                required = {"overview", "runtime", "sessions", "timeline", "tools", "security", "providers", "generated", "protected"}
                assert required.issubset(app._operations_trees), f"Missing UI tables: {required - set(app._operations_trees)}"
                assert app._operations_trees["sessions"].get_children(), "Session evidence did not render"
                overview_values = [app._operations_trees["overview"].item(item, "values") for item in app._operations_trees["overview"].get_children()]
                assert any("healthy" in [str(value).lower() for value in values] for values in overview_values), "Evidence integrity was not surfaced in overview"
                session_values = app._operations_trees["sessions"].item(app._operations_trees["sessions"].get_children()[0], "values")
                assert "smoke-session" in session_values, f"Session ID was not mapped to the Sessions row: {session_values}"
                file_values = app._operations_trees["files"].item(app._operations_trees["files"].get_children()[0], "values")
                assert "C:/tmp/a.py" in file_values, f"File path was not mapped to the Files row: {file_values}"
                tool_values = app._operations_trees["tools"].item(app._operations_trees["tools"].get_children()[0], "values")
                assert "high" in [str(value).lower() for value in tool_values], f"Tool risk was not mapped to the Tools row: {tool_values}"
                memory_values = app._operations_trees["memory"].item(app._operations_trees["memory"].get_children()[0], "values")
                assert str(root / "memory.md") in memory_values, f"Memory finding was not mapped to the Memory row: {memory_values}"
                for key, tree in app._operations_trees.items():
                    rows = tree.get_children()
                    if rows:
                        tree.selection_set(rows[0])
                        app._show_operation_detail(key)
                app.filter_var.set("codex")
                assert app.process_tree.get_children(), "Process filter removed its matching row"
                app.filter_var.set("no-such-agent")
                assert not app.process_tree.get_children(), "Process filter retained a nonmatching row"
                app.filter_var.set("")
                app._set_language("中文")
                translated_nav = [app._navigation.item(item, "text") for item in app._navigation.get_children()]
                assert any(value == "验证 / 恢复" for value in translated_nav), f"Navigation did not translate: {translated_nav}"
                app._set_language("English")
                for tab in app.notebook.tabs():
                    app.notebook.select(tab)
                    app.update_idletasks()
                app.update()
                width, height = app.winfo_width(), app.winfo_height()
                assert width <= 1360 and height <= 880, f"Window exceeded smoke viewport: {width}x{height}"
                assert app.notebook.winfo_width() > 0 and app.notebook.winfo_height() > 0, "Notebook has no layout size"

                selected_journal = app._journal_tree.get_children()[0]
                app._journal_tree.selection_set(selected_journal)
                app._select_journal()
                assert app._journal_var.get() == "smoke-journal", "Verify/recover selection was not captured"
                assert app._journal_tree.heading("verification", "text") == "Verification", "Journal verification column heading is ambiguous"

                class FakeRuntime:
                    def __init__(self):
                        self.database = Path(paths["database"])
                        self.calls = []
                    def run_action(self, action, **arguments):
                        self.calls.append((action, arguments, threading.current_thread().name))
                        return {"id": "smoke-journal", "success": True, "action": action}
                    def view(self):
                        return view
                fake = FakeRuntime()
                app._action_busy = False
                original_database_var = app.database_var
                class MainThreadOnlyVar:
                    def get(self):
                        if threading.current_thread() is not threading.main_thread():
                            raise AssertionError("Tk StringVar read from a worker thread")
                        return original_database_var.get()
                    def set(self, value):
                        return original_database_var.set(value)
                app.database_var = MainThreadOnlyVar()
                with patch.object(app, "_ensure_operations_runtime", return_value=fake):
                    app._run_operation("verify")
                    deadline = time.time() + 3
                    while time.time() < deadline and not fake.calls:
                        app.update()
                        time.sleep(0.01)
                    assert fake.calls and fake.calls[0][0] == "verify", f"Verify action was not dispatched: {fake.calls}"
                    assert fake.calls[0][2] != threading.current_thread().name, "Verify action ran on the Tk thread"
                    deadline = time.time() + 3
                    while app._action_busy and time.time() < deadline:
                        app.update()
                        time.sleep(0.01)
                    assert app._journal_var.get() == "smoke-journal", "Verify selection was lost after action"
                    app._run_operation("recover")
                    deadline = time.time() + 3
                    while len(fake.calls) < 2 and time.time() < deadline:
                        app.update()
                        time.sleep(0.01)
                    assert len(fake.calls) == 2 and fake.calls[1][0] == "recovery-preview", f"Recover action was not dispatched: {fake.calls}"
                assert not errors, "Tk callbacks failed: " + "; ".join(errors)
                print(json.dumps({"status": "passed", "tabs": len(app.notebook.tabs()), "tables": sorted(app._operations_trees), "isolated": True}))
            finally:
                app._close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
