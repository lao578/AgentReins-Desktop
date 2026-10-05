import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("agentreins_update_checker", ROOT / "portable" / "update_checker.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["agentreins_update_checker"] = MODULE
SPEC.loader.exec_module(MODULE)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class UpdateCheckerTests(unittest.TestCase):
    def test_version_order_and_prerelease(self):
        self.assertGreater(MODULE.parse_version("v1.2.0"), MODULE.parse_version("0.99.9"))
        self.assertGreater(MODULE.parse_version("1.2.0"), MODULE.parse_version("1.2.0-rc.1"))
        self.assertEqual(MODULE.parse_version("v0.1"), MODULE.Version(0, 1, 0, False))

    def test_selects_exact_host_install_artifacts(self):
        assets = [
            MODULE.ReleaseAsset("AgentReins.exe", "https://example.test/AgentReins.exe"),
            MODULE.ReleaseAsset("AgentReins-1.2.0-Windows-x64-Setup.exe", "https://example.test/setup.exe"),
            MODULE.ReleaseAsset("AgentReins-1.2.0-Linux-x86_64.AppImage", "https://example.test/app.AppImage"),
            MODULE.ReleaseAsset("AgentReins-1.2.0-macOS-universal.zip", "https://example.test/mac.zip"),
        ]
        self.assertEqual(MODULE.select_asset(assets, kind="portable", platform_name="windows").name, "AgentReins.exe")
        self.assertEqual(MODULE.select_asset(assets, kind="installer", platform_name="windows").name, "AgentReins-1.2.0-Windows-x64-Setup.exe")
        self.assertEqual(MODULE.select_asset(assets, kind="appimage", platform_name="linux").name, assets[2].name)
        self.assertEqual(MODULE.select_asset(assets, kind="macos", platform_name="macos").name, assets[3].name)
        self.assertIsNone(MODULE.select_asset(assets, kind="deb", platform_name="linux"))

    def test_check_uses_latest_stable_release_metadata(self):
        payload = {
            "tag_name": "v1.1.0",
            "html_url": "https://github.com/example/repo/releases/tag/v1.1.0",
            "published_at": "2026-10-05T00:00:00Z",
            "assets": [{"name": "AgentReins.exe", "browser_download_url": "https://example.test/a.exe", "size": 123}],
        }

        def opener(request, timeout):
            self.assertIsInstance(request, Request)
            self.assertEqual(timeout, 4)
            return FakeResponse(json.dumps(payload).encode())

        update = MODULE.check_for_updates("1.0.0", "example/repo", api_url="https://api.example.test", opener=opener, timeout=4)
        self.assertTrue(update.available)
        self.assertEqual(update.latest_version, "1.1.0")
        self.assertEqual(update.assets[0].name, "AgentReins.exe")

    def test_release_download_requires_and_verifies_checksum_sidecar(self):
        content = b"known release payload\n"
        digest = hashlib.sha256(content).hexdigest()
        asset = MODULE.ReleaseAsset("AgentReins.exe", "https://example.test/AgentReins.exe")
        sidecar = MODULE.ReleaseAsset("AgentReins.exe.sha256", "https://example.test/AgentReins.exe.sha256")
        expected = f"{digest}  AgentReins.exe\n".encode("ascii")

        def opener(request, timeout):
            if request.full_url.endswith(".sha256"):
                return FakeResponse(expected)
            return FakeResponse(content)

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / asset.name
            MODULE.download_and_verify_release_asset(asset, [asset, sidecar], destination, opener=opener)
            self.assertEqual(destination.read_bytes(), content)

    def test_mismatched_sidecar_fails_without_replacing_destination(self):
        asset = MODULE.ReleaseAsset("AgentReins.exe", "https://example.test/AgentReins.exe")
        sidecar = MODULE.ReleaseAsset("AgentReins.exe.sha256", "https://example.test/AgentReins.exe.sha256")

        def opener(request, timeout):
            if request.full_url.endswith(".sha256"):
                return FakeResponse(("0" * 64 + "  AgentReins.exe\n").encode("ascii"))
            return FakeResponse(b"different bytes")

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / asset.name
            destination.write_bytes(b"keep previous")
            with self.assertRaisesRegex(MODULE.UpdateCheckError, "SHA-256 mismatch"):
                MODULE.download_and_verify_release_asset(asset, [asset, sidecar], destination, opener=opener)
            self.assertEqual(destination.read_bytes(), b"keep previous")

    def test_cli_selects_platform_installer_from_release_assets(self):
        installer = MODULE.ReleaseAsset(
            "AgentReins-1.2.0-Windows-x64-Setup.exe", "https://example.test/setup.exe"
        )
        portable = MODULE.ReleaseAsset("AgentReins.exe", "https://example.test/portable.exe")
        sidecar = MODULE.ReleaseAsset(
            "AgentReins-1.2.0-Windows-x64-Setup.exe.sha256", "https://example.test/setup.exe.sha256"
        )
        release = MODULE.UpdateInfo("1.1.0", "1.2.0", True, "https://example.test/release", "v1.2.0", (installer, portable, sidecar))
        with tempfile.TemporaryDirectory() as directory, patch.object(MODULE, "check_for_updates", return_value=release), patch.object(
            MODULE, "_host_platform", return_value="windows"
        ), patch.object(MODULE, "download_and_verify_release_asset", return_value=Path(directory) / installer.name) as download:
            with redirect_stdout(io.StringIO()):
                status = MODULE.main(["--download", directory, "--kind", "installer"])
        self.assertEqual(status, 0)
        self.assertEqual(download.call_args.args[0].name, installer.name)

    def test_invalid_checksum_never_replaces_destination(self):
        asset = MODULE.ReleaseAsset("AgentReins.exe", "https://example.test/AgentReins.exe")
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / asset.name
            destination.write_bytes(b"old")
            with self.assertRaises(MODULE.UpdateCheckError):
                MODULE.download_asset(asset, destination, expected_sha256="0" * 64, opener=lambda *_a, **_k: FakeResponse(b"new"))
            self.assertEqual(destination.read_bytes(), b"old")


if __name__ == "__main__":
    unittest.main()
