# Changelog

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
