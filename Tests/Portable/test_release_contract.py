from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "agentreins_release_contract", ROOT / "portable" / "release_contract.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseContractTests(unittest.TestCase):
    def test_stable_tag_requires_exact_changelog_heading(self) -> None:
        version, channel = MODULE.validate_release_tag(
            "v1.2.3", "# Changelog\n\n## [1.2.3] - 2026-10-06\n"
        )
        self.assertEqual(version, "1.2.3")
        self.assertEqual(channel, "stable")

    def test_prerelease_tag_is_a_separate_channel(self) -> None:
        version, channel = MODULE.validate_release_tag(
            "v0.2.0-alpha", "## [0.2.0-alpha] - 2026-10-06\n"
        )
        self.assertEqual(version, "0.2.0-alpha")
        self.assertEqual(channel, "prerelease")

    def test_malformed_tag_is_rejected(self) -> None:
        with self.assertRaises(MODULE.ReleaseContractError):
            MODULE.validate_release_tag("v1.2", "## [1.2]\n")

    def test_missing_or_wrong_channel_heading_is_rejected(self) -> None:
        with self.assertRaises(MODULE.ReleaseContractError):
            MODULE.validate_release_tag("v1.2.3-alpha", "## [1.2.3] - stable\n")


if __name__ == "__main__":
    unittest.main()
