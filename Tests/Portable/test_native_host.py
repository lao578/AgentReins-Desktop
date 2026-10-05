import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / "portable" / "native_host.py"


class NativeHostTests(unittest.TestCase):
    def _exchange(self, event):
        with tempfile.TemporaryDirectory() as directory:
            environment = dict(os.environ, APPDATA=directory, XDG_DATA_HOME=directory)
            process = subprocess.Popen(
                [sys.executable, str(HOST), "--test"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            payload = json.dumps(event).encode("utf-8")
            process.stdin.write(struct.pack("<I", len(payload)) + payload)
            process.stdin.close()
            header = process.stdout.read(4)
            size = struct.unpack("<I", header)[0]
            response = json.loads(process.stdout.read(size))
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()
            evidence = Path(directory) / "AgentReins" / "web-agent-events.jsonl"
            return response, evidence.exists(), evidence.read_text() if evidence.exists() else ""

    def test_accepts_allowlisted_web_event(self):
        response, exists, contents = self._exchange({
            "schemaVersion": 1,
            "eventId": "test-1",
            "eventType": "connected",
            "url": "https://chatgpt.com/c/1",
        })
        self.assertEqual(response, {"ok": True, "eventId": "test-1"})
        self.assertTrue(exists)
        self.assertIn('"eventId":"test-1"', contents)

    def test_rejects_untrusted_url(self):
        response, exists, contents = self._exchange({
            "schemaVersion": 1,
            "eventId": "test-2",
            "eventType": "prompt",
            "url": "https://example.com/",
        })
        self.assertEqual(response, {"ok": False, "error": "evidence_not_allowed"})
        self.assertFalse(exists)
        self.assertEqual(contents, "")


if __name__ == "__main__":
    unittest.main()
