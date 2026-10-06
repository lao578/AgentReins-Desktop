import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "portable"))
import provider_config


class ProviderConfigTests(unittest.TestCase):
    def test_endpoint_discovery_never_returns_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "models.json"
            path.write_text(json.dumps({"api_key": "secret-value", "base_url": "https://user:password@gateway.example/v1/secret?api_key=hidden", "headers": {"Authorization": "Bearer token"}}), encoding="utf-8")
            before = path.read_bytes()
            result = provider_config.discover("codex", [path])
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["url"], "https://gateway.example")
            self.assertEqual(result[0]["identityStatus"], "configured_not_observed")
            self.assertEqual(path.read_bytes(), before)
            rendered = json.dumps(result)
            for value in ("secret-value", "password", "api_key", "hidden", "Bearer"):
                self.assertNotIn(value, rendered)

    def test_unknown_and_malformed_files_do_not_claim_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.json"
            path.write_text("invalid", encoding="utf-8")
            self.assertEqual(provider_config.discover("codex", [path, Path(temp) / "missing.json"]), [])


if __name__ == "__main__":
    unittest.main()
