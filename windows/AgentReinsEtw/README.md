# AgentReins Windows ETW helper

This optional helper captures mutation-oriented Windows kernel file events and
writes them as newline-delimited JSON. It is deliberately separate from the
portable collector: the normal application continues to use the unprivileged
polling watcher, while users who opt into ETW can run this process elevated.

## Build

The helper is Windows-only and requires the .NET 8 SDK:

```powershell
pwsh -File windows/AgentReinsEtw/build.ps1
```

The output is `dist/AgentReinsEtwHelper.exe`. The build uses the
`Microsoft.Diagnostics.Tracing.TraceEvent` package to consume the live kernel
session; no ETL files or registry changes are created.

## Run

Start an elevated PowerShell (Administrator) and limit tracing to the paths
that matter:

```powershell
AgentReinsEtwHelper.exe `
  --root "$env:USERPROFILE\Projects" `
  --output "$env:APPDATA\AgentReins\etw-events.jsonl"
```

Use `--max-log-mb 100` to rotate the JSONL file at a bounded size (the
default is 50 MiB; the previous file is retained as `.1`).

Each line contains `timestamp`, `path`, `action`, `source: "windows-etw"`,
`processId`, `operation`, and `isDirectory`. The helper exits cleanly on
Ctrl+C. ETW sessions are stopped on process disposal, including abnormal
shutdown handled by Windows.

The collector can consume this file directly (the default output path matches the collector's default `%APPDATA%` path):

```powershell
python portable/agentreins_portable.py watch --etw `
  --watch-path "$env:USERPROFILE\Projects"
```

If the helper is not started, has stopped, or cannot create a kernel session,
the collector automatically falls back to its normal polling watcher. ETW is
never enabled implicitly. For another output path, pass the same `--etw-events`
path to the collector's `watch --etw` command.

## Permissions and limitations

Starting a kernel ETW session normally requires an elevated administrator
process and can be blocked by endpoint policy. The helper only records file
metadata (not file contents); path filtering happens before JSON is written.
Read-only operations are ignored to keep the evidence stream focused on
changes. Kernel event names and payloads vary by Windows build, so unknown
records are skipped rather than guessed.
