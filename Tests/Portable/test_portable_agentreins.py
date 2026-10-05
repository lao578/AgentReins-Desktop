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
        self.assertEqual(record["schemaVersion"], 1)
        self.assertEqual(record["agents"][1]["processIds"], [43])
        json.dumps(record)

    def test_watch_output_is_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "nested" / "evidence.jsonl"
            MODULE.write_snapshot({"schemaVersion": 1}, destination)
            MODULE.write_snapshot({"schemaVersion": 1}, destination)
            lines = destination.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["schemaVersion"], 1)


if __name__ == "__main__":
    unittest.main()
