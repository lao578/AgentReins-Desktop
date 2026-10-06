import json
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "portable"))
from process_rules import IPGeolocationCache, ProcessController, ProcessMonitor, ProcessRuleStore, ProxyAccessLogReader, parse_rule_text


class ProcessRulesTests(unittest.TestCase):
    def test_parser_and_atomic_crud(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProcessRuleStore(Path(temp))
            rule = parse_rule_text("保护项目中的 .env，禁止读取和删除", project_root=str(Path(temp) / "repo"))
            self.assertEqual(rule["action"], "alert")
            self.assertIn("read", rule["ops"])
            store.add(rule)
            store.update(rule["id"], message="updated")
            self.assertEqual(store.list()[0]["message"], "updated")
            self.assertTrue(store.remove(rule["id"]))
            self.assertEqual(store.list(), [])

    def test_monitor_alerts_without_blocking(self):
        rule = {"id": "shell", "pattern": r"\brm\s+-rf\b", "severity": "critical", "action": "alert", "message": "danger"}
        alerts = ProcessMonitor([rule]).evaluate([{"pid": 12, "command": "rm -rf build", "agent": "codex", "startTime": 10}])
        self.assertEqual(alerts[0]["status"], "observed")
        self.assertEqual(alerts[0]["action"], "alert")

    def test_termination_requires_explicit_confirmation_and_identity(self):
        killed = []
        lookup = lambda pid: {"startTime": 20}
        controller = ProcessController(lookup, lambda pid: killed.append(pid))
        alert = {"pid": "12", "identity": {"startTime": 20}}
        self.assertEqual(controller.terminate(alert)["status"], "confirmation_required")
        self.assertEqual(controller.terminate(alert, explicit=True, expected_start_time=19)["status"], "identity_mismatch")
        result = controller.terminate(alert, explicit=True)
        self.assertTrue(result["success"])
        self.assertEqual(killed, [12])

    def test_public_ip_cache_requires_explicit_resolver(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = IPGeolocationCache(Path(temp) / "ips.json")
            self.assertIsNone(cache.lookup("192.168.1.1", lambda ip: {"country": "private"}))
            self.assertIsNone(cache.lookup("8.8.8.8"))
            result = cache.lookup("8.8.8.8", lambda ip: {"country": "US", "asn": 15169})
            self.assertEqual(result["country"], "US")
            self.assertEqual(cache.lookup("8.8.8.8")["asn"], 15169)

    def test_proxy_reader_only_projects_destination_and_is_incremental(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "v2ray.log"
            path.write_text("2026/10/06 12:00:00 from tcp:127.0.0.1:1234 accepted //tcp:Example.COM:443 secret-body\n", encoding="utf-8")
            reader = ProxyAccessLogReader(path)
            rows = reader.poll()
            self.assertEqual(rows[0]["remoteHost"], "example.com")
            self.assertNotIn("secret", json.dumps(rows))
            self.assertEqual(reader.poll(), [])


if __name__ == "__main__":
    unittest.main()
