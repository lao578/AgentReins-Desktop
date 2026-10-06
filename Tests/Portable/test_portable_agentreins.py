import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "portable"))
SPEC = importlib.util.spec_from_file_location("agentreins_portable", ROOT / "portable" / "agentreins_portable.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["agentreins_portable"] = MODULE
SPEC.loader.exec_module(MODULE)


class PortableRuntimeTests(unittest.TestCase):
    def test_build_version_resolver_normalizes_tags_and_defaults(self):
        self.assertEqual(MODULE.resolve_build_version("v1.2.3"), "1.2.3")
        self.assertEqual(MODULE.resolve_build_version("V0.1.1"), "0.1.1")
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(MODULE.resolve_build_version(), "0.1.1")

    def test_paths_follow_xdg_on_linux(self):
        with patch.object(MODULE.platform, "system", return_value="Linux"), patch.dict(
            os.environ, {"XDG_DATA_HOME": "/tmp/xdg-data", "XDG_CONFIG_HOME": "/tmp/xdg-config", "XDG_CACHE_HOME": "/tmp/xdg-cache"}, clear=False
        ):
            paths = MODULE.platform_paths()
        self.assertTrue(paths["data"].replace("\\", "/").endswith("/tmp/xdg-data/AgentReins"))
        self.assertTrue(paths["config"].replace("\\", "/").endswith("/tmp/xdg-config/AgentReins"))

    def test_agent_summary_and_schema(self):
        rows = [MODULE.ProcessRecord(42, 1, "claude-code --stdio", agent="claude"), MODULE.ProcessRecord(43, 42, "node cursor", agent="cursor")]
        self.assertEqual(MODULE.agent_summary(rows)[0]["id"], "claude")
        with patch.object(MODULE, "processes", return_value=rows), patch.object(MODULE, "network", return_value=[]), patch.object(MODULE.platform, "system", return_value="Linux"):
            record = MODULE.snapshot()
        self.assertEqual(record["schemaVersion"], 2)
        self.assertEqual(record["agents"][1]["processIds"], [43])
        json.dumps(record)

    def test_watch_output_is_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "nested" / "evidence.jsonl"
            MODULE.write_snapshot({"schemaVersion": 2}, destination)
            MODULE.write_snapshot({"schemaVersion": 2}, destination)
            lines = destination.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["schemaVersion"], 2)

    def test_sqlite_correlates_web_session_tool_and_file(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "evidence.sqlite3"
            store = MODULE.EvidenceStore(database)
            events = [{
                "eventId": "prompt-1",
                "eventType": "prompt",
                "provider": "chatgpt",
                "sessionId": "chatgpt:window:tab",
                "timestamp": "2026-10-05T00:00:00Z",
                "url": "https://chatgpt.com/c/1",
            }, {
                "eventId": "upload-1",
                "eventType": "upload",
                "provider": "chatgpt",
                "sessionId": "chatgpt:window:tab",
                "turnId": "prompt-1",
                "timestamp": "2026-10-05T00:00:01Z",
                "url": "https://chatgpt.com/c/1",
            }]
            store.append_web_events(events)
            context = store.latest_context()
            store.append_file_events([MODULE.FileChangeRecord("/tmp/work.txt", "modify", "test", MODULE.utc_now())], context)
            sessions = store.connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            tools = store.connection.execute("SELECT tool_name FROM tool_calls").fetchall()
            links = store.connection.execute("SELECT COUNT(*) FROM evidence_links WHERE source_kind='file_event'").fetchone()[0]
            store.close()
        self.assertEqual(sessions, 1)
        self.assertEqual(tools, [("browser.upload",)])
        self.assertEqual(links, 1)

    def test_evidence_chain_reports_health_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "evidence.sqlite3"
            store = MODULE.EvidenceStore(database)
            store.append_snapshot({
                "schemaVersion": 2,
                "timestamp": "2026-10-05T00:00:00Z",
                "platform": "test",
                "sourceCheckpoint": {"offset": 4, "inode": 9},
                "processes": [], "connections": [], "agents": [],
            })
            store.append_web_events([{
                "eventId": "chain-event", "eventType": "prompt",
                "provider": "codex", "sessionId": "chain-session",
                "timestamp": "2026-10-05T00:00:01Z", "sourceOffset": 12,
            }])
            healthy = store.integrity_report()
            self.assertEqual(healthy["status"], "healthy")
            self.assertEqual(healthy["count"], 2)
            checkpoint = store.connection.execute("SELECT source_checkpoint FROM evidence_chain WHERE id=1").fetchone()[0]
            self.assertEqual(json.loads(checkpoint)["offset"], 4)
            store.connection.execute("UPDATE evidence_chain SET source_checkpoint='tampered' WHERE id=1")
            store.connection.commit()
            self.assertEqual(store.integrity_report()["status"], "degraded")
            # Mutating the lossless source row is also detected, not just a
            # changed chain envelope.
            store.connection.execute("UPDATE snapshots SET payload='tampered' WHERE id=1")
            store.connection.commit()
            reasons = {item["reason"] for item in store.integrity_report()["errors"]}
            self.assertIn("payload_hash_mismatch", reasons)
            store.close()

    def test_optional_etw_jsonl_watcher_reads_events_and_tracks_heartbeat(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "etw-events.jsonl"
            path.write_text(json.dumps({
                "recordType": "status", "source": "windows-etw", "status": "started"
            }) + "\n" + json.dumps({
                "recordType": "file_event", "source": "windows-etw", "path": "C:/work/a.txt",
                "action": "modify", "timestamp": "2026-10-05T00:00:00Z", "processId": 42,
                "operation": "write", "sizeBytes": 12
            }) + "\n", encoding="utf-8")
            watcher = MODULE.EtwJsonlWatcher(path)
            events = watcher.poll()
            self.assertTrue(watcher.active)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].source, "windows-etw")
            self.assertEqual(events[0].details["processId"], 42)
            self.assertEqual(watcher.poll(), [])


if __name__ == "__main__":
    unittest.main()
