import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "portable"))
SPEC = importlib.util.spec_from_file_location("agent_adapters", ROOT / "portable" / "agent_adapters.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["agent_adapters"] = MODULE
SPEC.loader.exec_module(MODULE)


class NativeAgentAdapterTests(unittest.TestCase):
    def test_codex_prompt_tool_call_and_result_have_stable_ids(self):
        rows = [
            {"type": "event_msg", "timestamp": "2026-10-05T12:00:00Z", "payload": {
                "type": "item_completed", "turn_id": "turn-1", "item": {
                    "id": "prompt-row", "type": "UserMessage", "content": [{"type": "text", "text": "Inspect the tests"}]
                }}},
            {"type": "response_item", "timestamp": "2026-10-05T12:00:01Z", "payload": {
                "type": "function_call", "call_id": "call-1", "name": "shell", "arguments": "{\"cmd\":\"pytest\"}"}},
            {"type": "response_item", "timestamp": "2026-10-05T12:00:02Z", "payload": {
                "type": "function_call_output", "call_id": "call-1", "output": "3 passed"}},
        ]
        full = MODULE.parse_records("codex", rows, "/.codex/sessions/s1.jsonl", "s1")
        replay = MODULE.parse_records("codex", rows[1:], "/.codex/sessions/s1.jsonl", "s1")
        self.assertEqual([row["eventType"] for row in full], ["prompt", "tool_call", "tool_result"])
        self.assertEqual(full[1]["toolCallId"], full[2]["toolCallId"])
        self.assertEqual(full[1]["eventId"], replay[0]["eventId"])
        self.assertEqual(full[0]["turnId"], "turn-1")

    def test_claude_transcript_projects_tool_pair(self):
        rows = [
            {"type": "user", "uuid": "u1", "sessionId": "claude-session", "timestamp": "2026-10-05T12:00:00Z",
             "message": {"content": "Fix the parser"}},
            {"type": "assistant", "uuid": "a1", "sessionId": "claude-session", "timestamp": "2026-10-05T12:00:01Z",
             "message": {"model": "claude-test", "content": [
                 {"type": "text", "text": "I will run tests."},
                 {"type": "tool_use", "id": "tool-1", "name": "Bash", "input": {"command": "pytest"}},
             ]}},
            {"type": "user", "uuid": "u2", "sessionId": "claude-session", "timestamp": "2026-10-05T12:00:02Z",
             "message": {"content": [{"type": "tool_result", "tool_use_id": "tool-1", "content": "passed"}]}},
        ]
        events = MODULE.parse_records("claude", rows, "claude.jsonl", "claude-session")
        self.assertEqual([row["eventType"] for row in events], ["prompt", "response", "tool_call", "tool_result"])
        self.assertEqual(events[2]["toolCallId"], events[3]["toolCallId"])

    def test_workbuddy_native_function_call_pair(self):
        rows = [
            {"id": "prompt", "type": "message", "role": "user", "sessionId": "wb-1",
             "timestamp": "2026-10-05T12:00:00Z", "content": "Run the tests"},
            {"id": "same-row", "type": "function_call", "callId": "call-7", "name": "terminal",
             "sessionId": "wb-1", "timestamp": "2026-10-05T12:00:01Z", "arguments": "pytest"},
            {"id": "same-row", "type": "function_call_result", "callId": "call-7", "name": "terminal",
             "sessionId": "wb-1", "timestamp": "2026-10-05T12:00:02Z", "output": "passed"},
        ]
        events = MODULE.parse_records("workbuddy", rows, "workbuddy.jsonl", "wb-1")
        self.assertEqual([row["eventType"] for row in events], ["prompt", "tool_call", "tool_result"])
        self.assertEqual(events[1]["toolCallId"], events[2]["toolCallId"])
        self.assertNotEqual(events[1]["eventId"], events[2]["eventId"])

    def test_native_tool_events_project_to_one_sqlite_call(self):
        portable_spec = importlib.util.spec_from_file_location(
            "portable_under_test", ROOT / "portable" / "agentreins_portable.py"
        )
        portable = importlib.util.module_from_spec(portable_spec)
        assert portable_spec.loader is not None
        sys.modules["portable_under_test"] = portable
        portable_spec.loader.exec_module(portable)
        native = MODULE.parse_records("claude", [
            {"type": "assistant", "uuid": "a1", "sessionId": "same-session", "message": {"content": [
                {"type": "tool_use", "id": "id-local", "name": "Bash", "input": {"command": "pytest"}}
            ]}},
            {"type": "assistant", "uuid": "a2", "sessionId": "same-session", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "id-local", "content": "passed"}
            ]}},
        ], "claude.jsonl", "same-session")
        with tempfile.TemporaryDirectory() as temporary:
            store = portable.EvidenceStore(Path(temporary) / "evidence.sqlite3")
            store.append_web_events(native)
            row = store.connection.execute("SELECT tool_call_id,tool_name,status FROM tool_calls").fetchone()
            count = store.connection.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
            store.close()
        self.assertEqual(count, 1)
        self.assertEqual(row[0], "same-session:id-local")
        self.assertEqual(row[2], "completed")

    def test_cursor_database_reader_is_read_only_and_projects_latest_composer(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.vscdb"
            connection = sqlite3.connect(database)
            connection.executescript("CREATE TABLE composerHeaders(composerId TEXT,lastUpdatedAt INTEGER,value TEXT); CREATE TABLE cursorDiskKV(key TEXT PRIMARY KEY,value TEXT);")
            connection.execute("INSERT INTO composerHeaders VALUES(?,?,?)", (
                "composer-1", 100,
                json.dumps({"isDraft": False, "modelConfig": {"modelName": "cursor-test"}}),
            ))
            connection.executemany("INSERT INTO cursorDiskKV VALUES(?,?)", [
                ("bubbleId:composer-1:user-1", json.dumps({"bubbleId": "user-1", "type": 1, "text": "Review this code", "createdAt": 100})),
                ("bubbleId:composer-1:tool-1", json.dumps({"bubbleId": "tool-1", "type": 2, "createdAt": 101,
                    "toolFormerData": {"toolCallId": "call-9", "name": "run_terminal_command_v2", "params": "{\\\"command\\\":\\\"pytest\\\"}", "result": "passed", "status": "completed"}})),
            ])
            connection.commit()
            connection.close()

            reader = MODULE.NativeSessionReader(roots={}, cursor_databases=[database])
            events = reader.poll()
            self.assertEqual([row["eventType"] for row in events], ["prompt", "tool_call", "tool_result"])
            self.assertEqual({row["sessionId"] for row in events}, {"composer-1"})
            self.assertEqual(events[1]["toolCallId"], events[2]["toolCallId"])
            self.assertEqual(reader.poll(), [])

    def test_jsonl_reader_holds_incomplete_final_record_then_delivers_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".claude" / "projects"
            root.mkdir(parents=True)
            transcript = root / "session.jsonl"
            reader = MODULE.NativeSessionReader(roots={"claude": [root]}, cursor_databases=[])
            transcript.write_bytes(b'{"type":"user","uuid":"u1","sessionId":"s1","message":{"content":"hello"}}')
            self.assertEqual(reader.poll(), [])
            with transcript.open("ab") as handle:
                handle.write(b"\n")
            events = reader.poll()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["text"], "hello")
            self.assertEqual(reader.poll(), [])


if __name__ == "__main__":
    unittest.main()
