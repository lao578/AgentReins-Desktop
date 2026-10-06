import io
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "portable"))
from operations_cli import main as cli_main
from operations_runtime import OperationsRuntime
from turn_journal import VerificationRun, _now


class RuntimeHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "evidence % space.sqlite3"

    def connection(self):
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        return connection

    def test_partial_schema_and_malformed_history_are_reported_without_losing_valid_evidence(self):
        connection = self.connection()
        connection.execute("CREATE TABLE web_events(id INTEGER PRIMARY KEY,payload TEXT)")
        connection.executemany("INSERT INTO web_events(payload) VALUES(?)", [("not-json",), (json.dumps({"eventId": "p", "eventType": "prompt", "provider": "codex", "sessionId": "history", "turnId": "turn", "text": "Known prompt", "timestamp": "2026-10-06T00:00:00Z"}),)])
        connection.commit()
        connection.close()
        report = OperationsRuntime(self.database).view()
        self.assertEqual(report["sessions"][0]["id"], "history")
        self.assertEqual(report["summary"]["eventCount"], 1)
        self.assertEqual(report["historyHealth"]["errors"], ["Skipped malformed JSON in web_events"])
        # History loading never fabricates a pre-task checkpoint from old logs.
        self.assertEqual(report["journals"], [])

    def test_file_only_history_and_latest_runtime_graph_reload(self):
        connection = self.connection()
        connection.execute("CREATE TABLE file_events(id INTEGER PRIMARY KEY,timestamp TEXT,path TEXT,action TEXT,source TEXT,details TEXT)")
        connection.execute("INSERT INTO file_events VALUES(1,'2026-10-06T00:00:00Z','/project/app.py','modify','inotify','{}')")
        connection.execute("CREATE TABLE snapshots(id INTEGER PRIMARY KEY,payload TEXT)")
        snapshot = {"timestamp": "2026-10-06T00:00:01Z", "processes": [{"pid": 42, "ppid": 1, "agent": "codex", "command": "codex --serve"}], "connections": [], "collectorHealth": {"status": "degraded", "errors": [{"error": "fixture"}]}}
        connection.execute("INSERT INTO snapshots(payload) VALUES(?)", (json.dumps(snapshot),))
        connection.commit()
        connection.close()
        runtime = OperationsRuntime(self.database)
        first = runtime.run_action("history")
        self.assertEqual(first["files"][0]["details"]["path"], "/project/app.py")
        self.assertEqual(first["runtimeGraph"]["nodes"][0]["pid"], "42")
        self.assertEqual(first["collectorHealth"]["status"], "degraded")
        self.assertEqual(runtime.view()["summary"]["eventCount"], first["summary"]["eventCount"])

    def test_protection_and_memory_results_survive_runtime_restart(self):
        path = self.root / "memory.md"
        path.write_text("baseline", encoding="utf-8")
        runtime = OperationsRuntime(self.database)
        rule = runtime.run_action("protect", path=path)
        path.write_text("token: 'abcdefghijklmnop'\n", encoding="utf-8")
        view = runtime.observe({"timestamp": "2026-10-06T00:00:00Z"})
        self.assertEqual(view["protectionEvents"][0]["action"], "alert")
        report = runtime.run_action("scan-memory", targets=[path])
        self.assertTrue(report["findings"])
        reloaded = OperationsRuntime(self.database).view()
        self.assertEqual(reloaded["protectedFiles"][0]["id"], rule["id"])
        self.assertEqual(reloaded["memory"], report)
        self.assertEqual(reloaded["protectionEvents"], view["protectionEvents"])
        self.assertNotIn("abcdefghijklmnop", json.dumps(report))
        # Returned view is detached from internal state.
        reloaded["memory"]["inventory"].clear()
        self.assertTrue(runtime.view()["memory"]["inventory"])

    def test_incremental_observations_are_not_lost_by_competing_view_calls(self):
        runtime = OperationsRuntime(self.database)
        def observe(index):
            return runtime.observe({"nativeEvents": [{"eventId": str(index), "eventType": "tool_call", "provider": "codex", "sessionId": "session", "toolName": "read", "timestamp": f"2026-10-06T00:00:{index:02d}Z"}]})
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(observe, index) for index in range(12)] + [pool.submit(runtime.view) for _ in range(12)]
            for future in futures:
                future.result(timeout=15)
        self.assertEqual(runtime.view()["summary"]["eventCount"], 12)

    def test_cli_memory_and_protection_use_same_store(self):
        path = self.root / "memory.txt"
        path.write_text("ordinary memory", encoding="utf-8")
        def call(*args):
            out, err = io.StringIO(), io.StringIO()
            code = cli_main(["--database", str(self.database), *args], out, err)
            self.assertEqual(code, 0, err.getvalue())
            return json.loads(out.getvalue())
        rule = call("protection", "add", str(path))
        self.assertEqual(call("protection", "list")[0]["id"], rule["id"])
        self.assertEqual(call("memory", "scan", str(path))["inventory"][0]["path"], str(path))
        call("protection", "remove", rule["id"])
        self.assertEqual(call("protection", "list"), [])


@unittest.skipUnless(shutil.which("git"), "Git required")
class RuntimeJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.repo = root / "repository"
        self.repo.mkdir()
        self.database = root / "evidence.sqlite3"
        for args in (("init", "-q"), ("config", "user.email", "test@example.invalid"), ("config", "user.name", "Runtime Test"), ("config", "core.autocrlf", "false")):
            subprocess.run(["git", *args], cwd=self.repo, capture_output=True, check=True)
        (self.repo / "app.py").write_text("print('baseline')\n", encoding="utf-8")
        (self.repo / "package.json").write_text('{"scripts":{"test":"echo test"}}', encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-qm", "baseline"], cwd=self.repo, capture_output=True, check=True)

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        code = cli_main(["--database", str(self.database), *args], out, err)
        return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()

    def test_cli_explicit_preview_execute_failure_and_recovery_with_sqlite_reload(self):
        code, journal, err = self.cli("begin", str(self.repo), "--agent", "codex", "--prompt", "Synthetic task")
        self.assertEqual(code, 0, err)
        identity = journal["id"]
        (self.repo / "app.py").write_text("print('agent change')\n", encoding="utf-8")
        code, final, err = self.cli("finish", identity)
        self.assertEqual(code, 0, err)
        self.assertTrue(final["canRecoverSafely"])
        # Command detection previews argv; it does not accidentally execute npm.
        code, preview, err = self.cli("verify", identity)
        self.assertEqual(code, 0, err)
        self.assertFalse(preview["executed"])
        self.assertEqual(preview["commands"][0]["command"][-2:], ["run", "test"])
        marker = self.repo / "must-not-execute.txt"
        explicit = json.dumps([sys.executable, "-c", "from pathlib import Path; Path('must-not-execute.txt').write_text('ran')"])
        code, preview, err = self.cli("verify", identity, "--command-json", explicit)
        self.assertEqual(code, 0, err)
        self.assertFalse(marker.exists())
        failing = json.dumps([sys.executable, "-c", "import sys; print('failed assertion'); sys.exit(3)"])
        code, verification, err = self.cli("verify", identity, "--command-json", failing, "--execute")
        self.assertEqual(code, 1, err)
        self.assertEqual(verification["verificationRuns"][0]["exitCode"], 3)
        report = OperationsRuntime(self.database).view()
        self.assertEqual(report["verificationStates"][identity], "failed")
        self.assertEqual(report["journals"][0]["verificationRuns"][0]["exitCode"], 3)
        code, preview, err = self.cli("recover", identity)
        self.assertEqual(code, 0, err)
        self.assertFalse(preview["executed"])
        self.assertIn("agent change", (self.repo / "app.py").read_text())
        code, restored, err = self.cli("recover", identity, "--execute")
        self.assertEqual(code, 0, err)
        self.assertTrue(restored["success"])
        self.assertEqual((self.repo / "app.py").read_text(), "print('baseline')\n")

    def test_views_and_observation_remain_available_during_verification(self):
        runtime = OperationsRuntime(self.database)
        journal = runtime.run_action("begin", workspace=self.repo)
        started, release = threading.Event(), threading.Event()
        def blocked(*args, **kwargs):
            started.set()
            if not release.wait(10):
                raise AssertionError("verification was never released")
            return VerificationRun("fixture", _now(), 0.1, 0)
        import turn_journal
        with patch.object(turn_journal.ProjectVerifier, "run", side_effect=blocked):
            with ThreadPoolExecutor(max_workers=3) as pool:
                verifying = pool.submit(runtime.run_action, "verify", journal_id=journal["id"], commands=[[sys.executable, "-c", "pass"]])
                self.assertTrue(started.wait(5))
                try:
                    report = pool.submit(runtime.view).result(timeout=3)
                    self.assertEqual(report["verificationStates"][journal["id"]], "running")
                    pool.submit(runtime.observe, {"nativeEvents": [{"eventId": "independent", "eventType": "prompt", "sessionId": "other", "text": "hello"}]}).result(timeout=3)
                finally:
                    release.set()
                self.assertEqual(verifying.result(timeout=5)[0]["exitCode"], 0)


if __name__ == "__main__":
    unittest.main()
