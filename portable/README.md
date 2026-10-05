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
with `schemaVersion: 1`, making it straightforward for a future GUI or the
existing evidence database to consume.

## Windows desktop executable

The Tk desktop shell is packaged as a native, self-contained Windows EXE with
PyInstaller. From PowerShell on Windows (Python 3.9+), run:

```powershell
.\portable\build-windows.ps1
```

The output is `dist\AgentReins.exe`; it opens a small desktop console with
snapshot and watch controls and stores JSONL at the path shown in the window.
Use `-Clean` to remove previous PyInstaller output or `-OneDir` to produce a
debuggable directory build. PyInstaller builds are host-native, so a Windows
EXE must be built on Windows (Linux users can run the same Tk entry point from
source with `python3 portable/agentreins_desktop.py`).

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
