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
        self.assertIn("agentreins-install-service", script)
        self.assertIn("agentreins-uninstall-service", script)
        self.assertIn("install-native-host-linux.sh", script)
        uninstall = ROOT / "BrowserExtension" / "uninstall-native-host-linux.sh"
        self.assertTrue(uninstall.is_file())
        self.assertIn("NativeMessagingHosts", uninstall.read_text(encoding="utf-8"))

    def test_user_service_is_self_contained_and_persists_evidence(self) -> None:
        service = (ROOT / "packaging" / "linux" / "agentreins.service").read_text(
            encoding="utf-8"
        )
        installer = (ROOT / "packaging" / "linux" / "install-user-service.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("--output %h/.local/share/AgentReins/evidence.jsonl", service)
        self.assertIn("--database %h/.local/share/AgentReins/evidence.sqlite3", service)
        self.assertIn("portable/*.py", installer)
        self.assertIn('agentreins-portable', installer)
        self.assertIn("AgentReinsNativeHost", installer)
        self.assertIn('chmod 700 "$DATA_DIR"', installer)
        self.assertIn("install-native-host-linux.sh", installer)
        self.assertIn("uninstall-native-host-linux.sh", installer)

    def test_windows_install_ux_registers_chromium_and_hashes_all_binaries(self) -> None:
        install = (ROOT / "BrowserExtension" / "install-native-host.ps1").read_text(
            encoding="utf-8"
        )
        uninstall = (ROOT / "BrowserExtension" / "uninstall-native-host.ps1").read_text(
            encoding="utf-8"
        )
        build = (ROOT / "installers" / "windows" / "build-installer.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("HKCU:\\Software\\Chromium\\NativeMessagingHosts", install)
        self.assertIn("HKCU:\\Software\\Chromium\\NativeMessagingHosts", uninstall)
        self.assertIn("Write-Sha256Sidecar $nativeHost", build)
        self.assertIn("Write-Sha256Sidecar $etwHelper", build)

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
