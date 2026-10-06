# Changelog

## [0.2.0-alpha] - 2026-10-06

### Added

- Cross-platform Trace / Verify / Recover workflow with Git baselines,
  independent verification, guarded recovery previews, and SQLite persistence.
- Unified session, timeline, file, tool-call, provider, runtime, security, and
  memory projections in the Windows/Linux desktop console.
- SHA-256 evidence-chain integrity records with source checkpoints and live
  tamper status.
- Linux Native Messaging host bundled in AppImage and `.deb` packages, with
  per-user install and uninstall commands.
- Windows ETW opt-in helper and Linux inotify collection health reporting.

### Validation

- 90 portable tests pass (one symlink test skipped when the host disallows
  symlink creation).
- Windows and Linux desktop smoke tests run in CI; release artifacts include
  SHA-256 sidecars.

## [0.1.1] - 2026-10-05

### Added

- Optional elevated Windows ETW helper with heartbeat/fallback polling; ETW remains opt-in.
- Read-only native session adapters for Codex, Claude Code, Qoder, WorkBuddy, Kiro, Windsurf, and Cursor.
- Explicit GitHub update checker with SHA-256 sidecar verification and atomic downloads; no silent self-update.
- Windows Authenticode signing hooks when protected certificate secrets are configured.
- Chinese/English desktop UI, tray actions, autostart/background watch options, and build-version embedding.

## [0.1.0] - 2026-10-05

### Added

- Windows desktop executable (`AgentReins.exe`) and per-user Inno Setup installer.
- Chrome/Edge Native Messaging host with HTTPS provider allow-listing.
- Linux x86_64 AppImage, Debian package, desktop entry, and systemd user service.
- Cross-platform process/network collection with versioned JSONL and WAL-backed SQLite evidence.
- Linux inotify and Windows polling file-change collection, with browser session and tool-call correlation.
- Desktop status cards, process/network tables, filtering, sorting, auto-refresh, and optional tray mode.
- Preserved macOS universal app release and native host distribution.
