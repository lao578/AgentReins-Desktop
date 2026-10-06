from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class LinuxPackagingContractTests(unittest.TestCase):
    """Keep release packaging wired to the browser bridge and CLI assets."""

    def test_linux_package_contains_native_host_and_per_user_installer(self) -> None:
        script = (ROOT / "portable" / "package-linux.sh").read_text(encoding="utf-8")
        self.assertIn("build_native_host", script)
        self.assertIn('cp "$OUT/AgentReinsNativeHost"', script)
        self.assertIn("agentreins-install-native-host", script)
        self.assertIn("agentreins-uninstall-native-host", script)
        self.assertIn("install-native-host-linux.sh", script)
        uninstall = ROOT / "BrowserExtension" / "uninstall-native-host-linux.sh"
        self.assertTrue(uninstall.is_file())
        self.assertIn("NativeMessagingHosts", uninstall.read_text(encoding="utf-8"))

    def test_release_workflow_runs_tests_before_packaging(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "portable-release.yml").read_text(
            encoding="utf-8"
        )
        self.assertGreaterEqual(
            workflow.count("python -m unittest discover -s Tests/Portable"), 2
        )
        self.assertIn("bash -n portable/build-linux.sh portable/package-linux.sh", workflow)


if __name__ == "__main__":
    unittest.main()
