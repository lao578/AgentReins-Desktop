# Platform Parity Plan

This document defines what **complete feature parity** means for the macOS,
Windows, and Linux products. It is an engineering contract, not a claim that
the current portable build already has the same behavior as the native macOS
application.

## Scope and terminology

The macOS application is the reference implementation for product behavior.
Its primary source areas are `Sources/AgentReins/`, especially
`AgentOperationsCenterView`, `DevelopmentTrace`, `AgentSession`,
`EvidenceDatabase`, `TurnJournal`, `FileGuard`, the agent `*Sight` adapters,
`MemoryScanManager`, and `SemanticAnalyzer`.

Windows and Linux currently use the portable implementation in `portable/`:
the Python collector, Tk desktop shell, browser Native Messaging bridge, and
platform-specific process/network/file collectors. The portable runtime has a
useful normalized evidence boundary, but it is not a source-compatible port
of SwiftUI/AppKit.

The words below have precise meanings:

- **Equivalent behavior**: the same user-visible conclusion and evidence
  semantics, even when the operating-system API differs.
- **Observed**: collected directly from an OS or agent source.
- **Confirmed**: joined by a native stable identifier (for example a session
  or tool-call ID).
- **Inferred**: joined by a bounded heuristic such as timing or process
  ancestry. It must remain visibly labeled as inferred.
- **Unsupported**: the feature is not exposed by the platform build yet.

## Current capability matrix (portable parity branch, 2026-10-06)

The following reflects the current working tree after the portable parity port.
It distinguishes implemented portable behavior from remaining differences so
release notes do not claim source- or UI-level identity with macOS.

| Capability | macOS reference | Windows | Linux | Parity status |
| --- | --- | --- | --- | --- |
| Operations console and task stages | SwiftUI Operations Center with runtime graph, live task stages, security summary, and evidence inspector | Tk console with summary cards, runtime map, sessions/timeline/files/tools/security/provider views, Verify/Recover, Memory, process/network tables, filtering and raw JSON | Same Tk console and headless runtime | Partial: behavior is covered, but Tk layout and task-stage presentation are not SwiftUI-identical |
| Agent discovery and process lineage | `AgentDiscoveryManager`, `ProcessGuard`, native PID/PPID snapshots | CIM/PowerShell process snapshots with tasklist fallback, Agent process-tree scoping and process-rule backend | `/proc` with `ps` fallback, Agent process-tree scoping and process-rule backend | Partial: normalized lineage/runtime map exists; OS fields and rule UI differ |
| Native session adapters | WorkBuddy native; Codex, Cursor, Qoder, Claude compatibility/browser adapters | Read-only JSON/JSONL/SQLite adapters for Codex, Claude, Qoder, WorkBuddy and Cursor | Same portable adapters | Partial: Kiro is not a native adapter; transcript schemas and lifecycle depth remain best-effort |
| Prompt/model/tool/result lifecycle | `AgentSession` and adapter evidence with turn/tool correlation | Adapter events projected to sessions, timeline and tool calls; `TurnJournalStore` supports explicit begin/finish/ingest | Same | Partial: stable IDs and joins are present, but provider history and native lifecycle callbacks are incomplete |
| Durable evidence | SQLite WAL, raw evidence, checkpoints, health, integrity and idempotent replay | SQLite WAL snapshots/file/web/session/tool/link tables plus journal and operations state; append-only SHA-256 evidence chain records payload digests and opaque source checkpoints | Same | Partial: chain integrity and source checkpoints are implemented; the native raw-evidence envelope and full idempotent replay contract still differ |
| Browser Native Messaging | Swift host plus extension validation | Python host and install script; packaged Native Host executable | Python host packaged in AppImage/`.deb`, with per-user install command and manifest script | Near: protocol and validation are shared; AppImage users must extract the host before registering a stable path |
| File monitoring | Protected paths, backup, diff, code scan, optional restoration; one-second polling | Polling by default; explicit opt-in ETW JSONL helper with heartbeat and fallback; in-app protected-file backup/restore, preview, rule update and stale-state feedback | Recursive inotify with polling fallback; in-app protected-file backup/restore, preview, rule update and stale-state feedback | Partial: event quality and OS-level semantics still differ |
| Network evidence | PID-owned `lsof`, tool intent, Git/SSH projection, proxy destination refinement | PowerShell TCP snapshots scoped to Agent process tree plus adapter/tool intent and proxy refinement | `ss` snapshots scoped to Agent process tree plus adapter/tool intent | Partial: short-lived sockets and destination refinement differ by OS |
| Memory inventory and sensitive finding scan | Memory files, rules, scan, redact/delete/edit/restore workflow | `MemoryAuditor` inventory/scan/redact/delete-line/edit/restore backend; Memory tab exposes scan, redact, delete-line, edit, undo/restore and settings | Same | Partial: secure credential-store and native editor presentation still differ |
| Local semantic analysis | Redacts evidence, calls configured OpenAI-compatible endpoint, stores usage/result | Explicit Analysis tab/configure/analyze actions with local redaction and environment-only key | Same | Partial: secure OS credential-store integration and macOS result envelope are not yet matched |
| Code security scanning | Generated/changed code scanner with findings in evidence | `safety_features` scanner and Security/Generated-code tables in UI; confidence and source details available in row inspector | Same | Partial: turn-integrated finding attribution and full inspector parity remain |
| Independent verification | `ProjectVerifier` runs supported build/test commands and records exit/output | `TurnJournalStore.verify` detects Swift/Python/Node/Go/Rust commands, bounds output/time, and UI/CLI expose preview and execution | Same | Near: independent runs and evidence are implemented; project command coverage differs by platform |
| Turn baseline, mutation attribution, recovery | `TurnJournal`, Git snapshots, mutation comparison, guarded clean-baseline recovery | `TurnJournalStore` captures Git baseline/final snapshots, attribution, recovery preview and guarded execution; UI/CLI expose all stages | Same | Near: guard contract is implemented; raw source checkpoints and complete hook-level attribution remain |
| Notifications, menu/tray, background mode | Menu bar app and local notifications | Optional `pystray`/Pillow tray; taskbar fallback and background mode | Optional tray; desktop-environment dependent | Partial |
| Updates and release artifacts | macOS release workflow and package | EXE/Setup/Native Host/ETW helper workflows | AppImage/`.deb`/systemd user service workflows | Packaging parity; clean-VM install/signing/notarization validation remains |
## Current implementation evidence (portable parity branch)

The following modules are present in the working tree and are usable from both
headless and desktop clients. They are intentionally local-first and return
serializable dictionaries so evidence can be rendered, persisted, or exported
without depending on Tk.

| Module / surface | Implemented behavior | Current verification |
| --- | --- | --- |
| `portable/evidence_projection.py` | Normalized sessions, timeline, tool calls, file/network intent, provider trust, context/SSH/token findings, runtime graph and collector-health projection | `Tests/Portable/test_evidence_projection.py`; desktop smoke validates session/file/tool/memory mapping |
| `portable/turn_journal.py` | Git baseline/final snapshots, mutation attribution, explicit begin/finish/ingest, independent verify with bounded output/time, guarded recovery preview/execution, JSON/SQLite persistence | `Tests/Portable/test_turn_journal.py`, `test_operations_runtime.py`; Verify/Recover tab and CLI call the same service |
| `portable/safety_features.py` | Code/tool/MCP/Skill/external-content/context scanners; protected-file SHA-256 backups/diff/restore; memory inventory, redaction, delete-line/edit/restore; optional OpenAI-compatible semantic analysis with local redaction | `Tests/Portable/test_safety_features.py`; no real provider request is made by tests |
| `portable/operations_runtime.py` and `operations_cli.py` | Thread-safe shared facade, SQLite history hydration, `history/report`, `begin/finish`, `verify`, `recovery-preview/recover`, protection, memory and analysis actions | `Tests/Portable/test_operations_runtime.py`; CLI uses argv-only verification commands |
| `portable/agent_adapters.py` | Incremental, read-only Codex/Claude/Qoder/WorkBuddy/Cursor JSON/JSONL and Cursor SQLite adapters with stable IDs, rotation/partial-row handling and workspace metadata | `Tests/Portable/test_agent_adapters.py`; provider schemas remain best-effort and version-sensitive |
| `portable/agentreins_portable.py` | Agent process-tree scoping, Windows PowerShell and Linux `/proc`/`ss` collectors, recursive inotify, opt-in ETW JSONL helper with heartbeat/fallback, SQLite evidence tables, append-only SHA-256 evidence chain/source checkpoints and collector health | Portable collector tests cover chain health/tamper detection; live ETW/inotify overflow and permission fixtures still pending |
| `portable/process_rules.py` and `provider_config.py` | Process-rule matching/alerts/explicit controller actions, PID-reuse protection, IP geolocation cache, proxy access-log parsing, and read-only provider configuration with credential redaction | `Tests/Portable/test_process_rules.py`, `test_provider_config.py`; live OS process-rule enforcement and provider-specific fixtures remain |
| `portable/agentreins_desktop.py` | Tk desktop with Overview, Runtime map, Sessions, Timeline, Files, Tools, Security, External services, Generated code, Protected files, Verify/Recover, Memory, AI analysis, Processes, Connections and Raw JSON; filtering, auto-refresh, language switch and optional tray/background | `portable/desktop_smoke.py` validates 16 tabs, operation tables and worker actions; visual parity with SwiftUI is not claimed |

The safety domain is implemented independently of collection. The analyzer stores
only endpoint/model/environment-variable name. Set the configured variable,
normally `AGENTREINS_ANALYSIS_API_KEY`, before explicitly requesting analysis;
the plaintext key is not persisted. Memory SQLite files are inventoried and
scanned read-only; edits apply only to owning text files, with guarded backups.

### Backend versus current desktop UI

Backend and UI coverage now differ as follows:

| Backend operation | Current portable desktop surface | Remaining gap |
| --- | --- | --- |
| Code/tool/external/context assessments | Security and Generated code tables plus row detail; timeline/session/tool joins expose confidence | Add a richer source-event/rule inspector and turn-level attribution |
| Protected-file `preview`, `restore`, `update_rule` | Protected-files table exposes preview, rule update, restore and remove actions; stale fingerprints are enforced by backend | Native macOS rule editor and layout differ |
| Memory settings, scan, redact, delete-line, edit, restore | Memory tab exposes scan, folder scan, finding redact, delete-line, edit and undo/restore plus settings editor | Native macOS editor and secure-store presentation differ |
| Semantic configure/analyze/remove | AI analysis tab exposes endpoint/model/key-variable configuration and explicit analyze action after confirmation | Add configuration removal and clearer disabled/secure-store state; key is currently environment-backed |
| Turn verify/recover | Verify/Recover tab and worker actions call verify, recovery-preview, then confirmation-gated recover; CLI exposes the same stages | Expand command detection and show richer independent stdout/stderr/timeout evidence |

Release notes should call the first column **portable backend capabilities** and
use **interactive parity** only for actions exposed by the second column. The
portable build is not a source-compatible SwiftUI/AppKit port.
## Target parity contract

Windows and Linux may use different collectors, but the following contracts
must be identical across all three platforms:

1. **Normalized event model**: prompt, model request/response, tool request,
   tool result, process, network, file, verification, and recovery events use
   the same required fields and schema version.
2. **Evidence semantics**: every join carries `confirmed`, `inferred`, or
   `unknown`; missing data is never promoted to a fact by UI wording.
3. **Turn lifecycle**: a turn has a stable ID, a baseline captured before the
   first observed mutation, a final snapshot, mutation list, verification
   runs, terminal status, and a durable source checkpoint.
4. **Independent verification**: verification is launched by AgentReins,
   separate from the agent's own result, and records command, start/end,
   duration, stdout/stderr limits, exit status, timeout, and environment.
5. **Recovery guard**: recovery is previewable and refuses to run if the
   baseline was dirty, the recorded HEAD changed, or the workspace changed
   after the turn. It must never delete a path outside the repository root.
6. **UI conclusions**: the same concepts are available in the desktop UI:
   agent fleet, live task, process/runtime details, network destinations,
   files, verification, provider exposure, and recovery preview.

Platform-specific differences are acceptable only beneath these contracts.
For example, ETW/inotify/FSEvents may produce different low-level records, but
their normalized file events must preserve action, path, timestamp, source,
and confidence.

## Porting workstreams and remaining work

The original workstreams are retained as an implementation checklist. Items
marked **implemented** are in the current portable branch; **remaining** items
are the reasons the matrix still contains `Partial` or `Near` entries.

### P0: shared domain and persistence — mostly implemented

- **Implemented:** versioned normalized events, `TurnJournalStore`, SQLite WAL
  persistence for snapshots/files/web/session/tool/link rows, journal payloads,
  operations state, and JSON report/export paths.
- **Implemented:** accepted snapshots, file events and native/web events now
  receive deterministic SHA-256 payload digests in an append-only chain. Each
  record stores an opaque source checkpoint (offset, inode/rotation tuple,
  ETW sequence, or adapter event ID), and `OperationsRuntime.view()` exposes
  `evidenceIntegrity` with a tamper/degradation status.
- **Remaining:** a macOS-equivalent raw-evidence envelope and full idempotent
  replay/checkpoint recovery semantics. The chain is an integrity signal, not
  a claim that every provider's source log can be reconstructed.

### P1: trace and attribution — implemented with conservative joins

- **Implemented:** adapter events project into sessions, timeline, tool calls,
  files, network intent, provider/context reports and runtime graph; process
  and connection rows are scoped to Agent process trees; confidence is shown
  as `confirmed`, `inferred` or `unknown`.
- **Remaining:** complete provider lifecycle callbacks and hook-level mutation
  attribution. Transcript adapters remain read-only and best-effort.

### P2: verify and recover — implemented, broaden coverage next

- **Implemented:** project command detection for Swift, Python, Node, Go and
  Rust; argv-only verification with bounded output and timeout; independent
  verification evidence; preview-first guarded recovery with Git/path/HEAD and
  post-recovery checks.
- **Remaining:** broader project command profiles (`pwsh`, `cmd`, native build
  executables), cancellation UX and richer stdout/stderr/timeout presentation.

### P3: security and analysis — backend and portable UI implemented

- **Implemented:** generated-code/tool/external/context scanners; protected
  files and backups with preview/rule-update actions; memory inventory and
  guarded redaction/edit/delete-line/undo/restore plus settings editor;
  explicit redacted OpenAI-compatible analysis; all are available through
  `OperationsRuntime` and the desktop's Security, Generated code, Protected,
  Memory and AI analysis pages.
- **Remaining:** richer security inspectors, configuration removal, and secure
  OS credential-store integration. Portable controls are implemented but are
  not a source-compatible SwiftUI editor.

### P4: native collection quality — platform fallback implemented

- **Implemented:** Linux recursive inotify, Windows opt-in ETW JSONL helper with
  heartbeat/fallback, polling fallback on both platforms, explicit collector
  health/errors, process-tree scoping and proxy/destination refinement.
- **Remaining:** clean-VM package/service validation, signing/notarization and
  automatic update rollout. Deterministic ETW heartbeat/rotation and inotify
  overflow/permission fixtures are covered by portable tests; live OS behavior
  still needs manual validation. Payload contents and remote-host filesystem
  activity remain outside the local evidence boundary.
## Cross-platform fixture and acceptance plan

Fixtures must be deterministic, synthetic, and contain no real prompts,
credentials, or proprietary source. Store portable fixtures under
`Tests/Fixtures/PortableParity/` and platform-specific capture fixtures under
`Tests/Fixtures/PortableParity/<platform>/`.

### Required fixture sets

| Fixture | Purpose | Required assertions |
| --- | --- | --- |
| `turn-basic` | Prompt, model response, one tool call/result, one file update | Same normalized IDs, lifecycle states, and final mutation on all platforms |
| `turn-preexisting-dirty` | Workspace has an unrelated modified file before prompt | Baseline records it; recovery is refused; unrelated file is preserved |
| `turn-untracked-and-rename` | Agent creates an untracked file and renames a tracked file | Create/rename are represented without path traversal; preview is accurate |
| `verification-pass-fail-timeout` | Commands exit 0, non-zero, and exceed timeout | Independent result is separate from agent claim; stdout/stderr and timeout are bounded |
| `adapter-rotation-partial-jsonl` | Log truncation, replacement, and incomplete final line | No duplicate events; partial row is retried; checkpoint advances only on complete rows |
| `network-intent-vs-socket` | Tool URL remains after short socket closes | Intent is retained; missing socket is marked unknown, never inferred as observed |
| `file-events-overflow` | Linux inotify overflow and Windows ETW heartbeat expiry | Health becomes degraded; fallback starts; gaps are disclosed |
| `browser-native-message` | Prompt/upload/result from a browser extension | Native IDs produce confirmed session/tool links and invalid messages are rejected |
| `memory-redaction` | Synthetic token/private-key patterns | Local findings are redacted before optional analysis; original remains recoverable locally |
| `semantic-disabled` | No configured key/secure store | No network request; UI explains unavailable rather than failing silently |
| `recovery-path-escape` | Mutation path attempts `..` or absolute escape | Recovery refuses the operation and records the reason |

### Acceptance gates

Before calling Windows or Linux feature-complete, CI and a manual smoke run
must demonstrate:

- `python -m unittest discover -s Tests/Portable -p 'test_*.py'` passes;
- the same parity fixture produces equivalent normalized JSON (ignoring OS PID,
  path separator, executable name, and timestamp precision);
- a clean Git fixture can be verified and recovered, while dirty-baseline and
  post-turn workspace changes are refused;
- collector interruption, malformed input, permission denial, and database
  restart are visible in health/evidence output;
- browser Native Messaging, tray/background mode, and package installation
  work on a clean Windows VM and a clean Linux VM/desktop session;
- no feature is advertised as confirmed when the platform source only provides
  a timed or process-based inference.

The parity effort is complete only when the matrix above has no `Missing` or
`Partial` entries for the target release, or each remaining exception is
explicitly approved and documented as a platform limitation in the release
notes.









