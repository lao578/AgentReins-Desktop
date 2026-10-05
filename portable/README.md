# AgentReins Portable Runtime

`AgentReins.app` remains the macOS SwiftUI console. Windows and Linux cannot
compile SwiftUI/AppKit, so this directory provides the equivalent local-first
collector as a dependency-free Python 3.9+ CLI. It intentionally uses the
same evidence boundary as the macOS collectors: process/parent lineage and
open TCP destinations. It never reads packet payloads, injects into agents, or
requires administrator/root privileges.

## Run

```bash
# Linux
./portable/agentreins-portable.sh snapshot
./portable/agentreins-portable.sh watch --interval 2 --output "$XDG_DATA_HOME/AgentReins/evidence.jsonl"

# Windows PowerShell
.\portable\agentreins-portable.ps1 snapshot
.\portable\agentreins-portable.ps1 watch --interval 2 --output "$env:APPDATA\AgentReins\evidence.jsonl"
```

`paths` prints the resolved data/config/cache locations. The output is JSONL
with `schemaVersion: 2`; `watch` also writes a WAL-backed SQLite database and
records file events. Linux uses inotify when available. Windows uses a safe
polling fallback in restricted environments; an ETW provider can be enabled
later without changing the normalized event schema.

## Windows desktop executable

The Tk desktop shell is packaged as a native, self-contained Windows EXE with
PyInstaller. From PowerShell on Windows (Python 3.9+), run:

```powershell
.\portable\build-windows.ps1
```

The output is `dist\AgentReins.exe`; it opens a small desktop console with
snapshot and watch controls and stores JSONL at the path shown in the window.
The same build also emits `dist\AgentReinsNativeHost.exe`, the Chrome/Edge
Native Messaging bridge used by the browser extension. The Windows installer
copies and registers this host automatically.
Use `-Clean` to remove previous PyInstaller output or `-OneDir` to produce a
debuggable directory build. PyInstaller builds are host-native, so a Windows
EXE must be built on Windows (Linux users can run the same Tk entry point from
source with `python3 portable/agentreins_desktop.py`).
Release builds include `pystray`/Pillow when available for a real tray icon;
source installs can enable the same experience with `python -m pip install
pystray Pillow`. Without those optional packages, **Background** safely
minimizes to the taskbar.

Every push to `main` also builds `AgentReins.exe` in GitHub Actions and makes
it available as the `AgentReins-Windows-x64` workflow artifact. Tagged
releases publish the executable, Native Host, SHA-256 file, and Setup
installer directly on GitHub Releases.

## Linux desktop packages

The tagged-release workflow builds an x86_64 AppImage and Debian package. To
build them locally on an Ubuntu/Debian machine, install Tk and PyInstaller,
then run:

```bash
sudo apt install python3-tk dpkg-dev
python3 -m pip install --user pyinstaller
./portable/package-linux.sh all
```

The artifacts are written to `dist/`:

- `AgentReins-<version>-Linux-x86_64.AppImage` is a portable GUI package;
  make it executable (`chmod +x ...`) and launch it directly.
- `AgentReins-<version>-Linux-amd64.deb` installs the GUI as `agentreins` and
  the collector CLI as `agentreins-portable`.

After installing the Debian package, the collector can run as a per-user
systemd service (no root access is needed for collection):

```bash
systemctl --user daemon-reload
systemctl --user enable --now agentreins.service
systemctl --user status agentreins.service
```

The service writes to `~/.local/share/AgentReins/evidence.jsonl`; disable it
with `systemctl --user disable --now agentreins.service`. The AppImage build
uses `appimagetool` from `PATH`, or downloads the matching tool into
`build/linux-package/` when running in CI. Set `APPIMAGETOOL=/path/to/tool` to
use a pinned local copy.

For a persistent local database:

```powershell
.\portable\agentreins-portable.ps1 watch --database "$env:APPDATA\AgentReins\evidence.sqlite3"
```

The SQLite database contains `snapshots`, `file_events`, `web_events`,
`sessions`, `tool_calls`, and `evidence_links`. Browser Native-Messaging
events are projected into sessions/tool calls; file changes are linked to the
most recent observed session/tool context with `inferred` confidence. Linux
uses recursive inotify watches. Windows uses a safe polling watcher in this
release; kernel ETW is not started implicitly because doing so changes system
tracing policy and commonly needs elevated rights.

### Platform collectors

| Platform | Process source | Network source | Fallback |
| --- | --- | --- | --- |
| Linux | `/proc/<pid>` | `ss -H -tanp` | `ps`, `lsof` |
| Windows | PowerShell CIM `Win32_Process` | PowerShell `Get-NetTCPConnection` | empty snapshot with explicit capabilities |
| macOS | `ps` | `lsof` | empty snapshot |

PowerShell is part of supported Windows installations. If a restricted
environment blocks CIM or `Get-NetTCPConnection`, the collector still emits a
valid snapshot and does not fail the whole run.

## Verify

```bash
python3 -m unittest discover -s Tests/Portable -p 'test_*.py'
```
