import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("agentreins_portable", ROOT / "portable" / "agentreins_portable.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["agentreins_portable"] = MODULE
SPEC.loader.exec_module(MODULE)


class PortableRuntimeTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
