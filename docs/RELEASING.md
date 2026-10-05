# Release Process

AgentReins CI builds a Universal 2 macOS application containing both `arm64` and `x86_64` code, a Windows executable/installer, and Linux AppImage/`.deb` packages. Pull requests and pushes to `main` may build unsigned development artifacts. Apple Developer ID signing/notarization and Windows Authenticode signing are enabled when their protected secrets are configured; missing secrets do not block a release, and CI reports unsigned/unnotarized artifacts explicitly. All release binaries/packages publish SHA-256 sidecars.

## Required GitHub secrets for trusted distribution

| Secret | Purpose |
| --- | --- |
| `APPLE_CERTIFICATE_P12` | Base64-encoded Developer ID Application certificate and private key. |
| `APPLE_CERTIFICATE_PASSWORD` | Password used when exporting the `.p12`. |
| `APPLE_ID` | Apple ID used by the notarization service. |
| `APPLE_TEAM_ID` | Apple Developer Team ID. |
| `APPLE_APP_PASSWORD` | App-specific password used by `notarytool`. |
| `WINDOWS_SIGNING_CERT_P12` | Base64-encoded Authenticode Code Signing PFX for Windows artifacts (including the optional ETW helper). |
| `WINDOWS_SIGNING_CERT_PASSWORD` | Password used to open the Authenticode PFX. |

The Windows certificate secrets are optional. When both are configured, CI signs `AgentReins.exe`, the Native Messaging host, and the installer with SHA-256 and an RFC 3161 timestamp, then verifies each signature before calculating release checksums. Configure both or neither. If absent, CI explicitly reports that the release binaries are unsigned. Do not interpret a SHA-256 checksum as a publisher signature: checksums detect transfer corruption but do not authenticate the publisher.

Without Apple secrets, CI still publishes an ad-hoc-signed macOS development archive; Gatekeeper may warn when it is opened. If Developer ID signing is configured but notarization credentials are absent, the app will be signed but not notarized. A trusted macOS distribution requires signing, notarization, stapling, and tests on a clean Intel Mac and a clean Apple Silicon Mac.

## Create a release

1. Confirm that the `main` workflow passes.
2. Update user-facing release notes and decide the semantic version.
3. Create and push an annotated tag:

   ```bash
   git tag -a v1.1.0 -m "Release AgentReins 1.1.0"
   git push origin v1.1.0
   ```

4. The workflow builds both architectures, signs/notarizes the macOS app when credentials exist, creates a ZIP archive and SHA-256 checksum, and publishes the GitHub Release. Windows/Linux jobs attach their packages and checksums to that same release. Windows artifacts are Authenticode-signed when both Windows signing secrets are set; the CI logs clearly state when the output is unsigned.
5. Download the archive while signed out of GitHub and test it on clean Intel and Apple Silicon systems.

## Architecture verification

```bash
lipo -archs AgentReins.app/Contents/MacOS/AgentReins
```

The command must print both `x86_64` and `arm64`.

## Update checks and verified downloads

Release metadata is sourced from the public GitHub Releases API at
`lao578/AgentReins-Desktop`; there is no separate update server. The portable
update-check module compares stable semantic-version tags, selects a matching
host package, and downloads only after locating an API SHA-256 digest or the
release's matching `.sha256` sidecar. It writes to a temporary file and
atomically renames only after the hash matches. It does **not** install,
replace, or restart AgentReins. The user must explicitly launch the downloaded
installer/package, and the normal platform signature checks still apply.

Run the checker from a Python 3.9+ checkout:

```powershell
python portable/update_checker.py --current-version 0.1.1 --check
python portable/update_checker.py --current-version 0.1.1 --download "$env:TEMP\AgentReins-updates" --kind installer
```

```bash
python3 portable/update_checker.py --current-version 0.1.1 --check
python3 portable/update_checker.py --current-version 0.1.1 --download "$HOME/Downloads/AgentReins" --kind appimage
```

Supported `--kind` values are `portable`, `installer`, `appimage`, `deb`, and
`macos`. The desktop UI's update action is explicit: it checks release metadata
and verifies a selected download, but never silently installs, replaces, or
restarts the app. Offline/API errors are returned as structured JSON and do
not block normal app use.

## Release safety

- Never commit certificates, passwords, API keys, or notarization credentials.
- Store signing materials only as protected GitHub Actions secrets and use a short-lived runner. Never expose signing secrets to pull-request workflows from forks.
- Protect the GitHub release environment before storing production secrets.
- Do not describe an ad-hoc build as signed for public distribution.
- Do not publish a tag until the application version, release notes, and implemented capabilities agree.
