#!/usr/bin/env python3
"""Headless access to AgentReins operations (all output is UTF-8 JSON).

Examples::

    python -m portable.operations_cli --database evidence.sqlite3 history
    python -m portable.operations_cli begin /path/to/project --prompt "Fix tests"
    python -m portable.operations_cli verify JOURNAL_ID
    python -m portable.operations_cli verify JOURNAL_ID --execute
    python -m portable.operations_cli recover JOURNAL_ID --execute

Verification/recovery default to preview. Pass --execute to run the displayed
commands or approved recovery. Explicit argv commands use --command-json;
shell metacharacters are never interpreted by this CLI.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sqlite3
import sys
from pathlib import Path
from typing import Any, Sequence, TextIO

try:
    from operations_runtime import OperationsRuntime
except ImportError:
    from .operations_runtime import OperationsRuntime


def default_database() -> Path:
    system = platform.system()
    if system == "Windows":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif system == "Darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return root / "AgentReins" / "evidence.sqlite3"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="AgentReins operations: trace, verify, recover and inspect evidence")
    result.add_argument("--database", type=Path, default=default_database(), help="Evidence SQLite path")
    result.add_argument("--output", type=Path, help="Write JSON to this file instead of stdout")
    sub = result.add_subparsers(dest="command", required=True)
    for name in ("history", "report"):
        command = sub.add_parser(name, help="Read stored evidence, journals and assessments")
        command.add_argument("--session", help="Filter event/session/journal rows by native session ID")
    command = sub.add_parser("begin", help="Capture a checkpoint before starting an agent task")
    command.add_argument("workspace", type=Path)
    command.add_argument("--prompt", default="")
    command.add_argument("--agent", default="manual")
    command.add_argument("--session-id")
    command.add_argument("--turn-id")
    command = sub.add_parser("finish", help="Capture the final workspace state")
    command.add_argument("journal_id")
    command.add_argument("--status", choices=("completed", "failed", "cancelled", "stuck"), default="completed")
    command = sub.add_parser("verify", help="Preview detected build/test commands; --execute runs them")
    command.add_argument("journal_id")
    command.add_argument("--execute", action="store_true")
    command.add_argument("--timeout", type=float, default=300)
    command.add_argument("--command-json", action="append", help='Explicit argv JSON array, repeatable: ["python", "-m", "pytest"]')
    for name in ("recovery-preview", "recover"):
        command = sub.add_parser(name, help="Preview guarded recovery" if name == "recovery-preview" else "Preview recovery; --execute restores the recorded clean baseline")
        command.add_argument("journal_id")
        if name == "recover":
            command.add_argument("--execute", action="store_true")
    command = sub.add_parser("protection", help="Manage local protected-file rules")
    protection = command.add_subparsers(dest="protection_action", required=True)
    add = protection.add_parser("add", help="Back up a file and watch for changes")
    add.add_argument("path", type=Path)
    add.add_argument("--auto-restore", action="store_true", help="Explicitly opt in to automatic restoration while monitoring")
    protection.add_parser("list", help="List protected-file rules")
    remove = protection.add_parser("remove", help="Remove a protected-file rule")
    remove.add_argument("rule_id")
    command = sub.add_parser("memory", help="Read-only sensitive-memory inspection")
    memory = command.add_subparsers(dest="memory_action", required=True)
    scan = memory.add_parser("scan", help="Scan target files/directories, or discovered agent memory by default")
    scan.add_argument("targets", nargs="*", type=Path)
    return result


def _filter_report(report: dict[str, Any], session: str | None) -> dict[str, Any]:
    if not session:
        return report
    report["sessions"] = [item for item in report.get("sessions", []) if item.get("id") == session]
    for name in ("timeline", "files", "toolCalls", "journals", "generatedCode", "externalContent", "contextReports"):
        report[name] = [item for item in report.get(name, []) if item.get("sessionId") == session]
    report["filter"] = {"sessionId": session, "scope": "Session rows filtered; runtime and global assessments remain global."}
    return report


def dispatch(runtime: OperationsRuntime, args: argparse.Namespace) -> tuple[Any, int]:
    command = args.command
    if command in {"history", "report"}:
        runtime.run_action(command)
        return _filter_report(runtime.view(), args.session), 0
    if command == "begin":
        return runtime.run_action("begin", workspace=args.workspace, prompt=args.prompt, agent=args.agent, session_id=args.session_id, turn_id=args.turn_id), 0
    if command == "finish":
        return runtime.run_action("finish", journal_id=args.journal_id, status=args.status), 0
    if command == "verify":
        if args.timeout <= 0 or args.timeout > 86_400:
            raise ValueError("Verification timeout must be between 0 and 86400 seconds")
        commands = [json.loads(raw) for raw in args.command_json] if args.command_json else None
        preview = runtime.run_action("verification-preview", journal_id=args.journal_id, commands=commands)
        if not args.execute:
            return {"journalId": args.journal_id, "executed": False, "commands": preview}, 0
        runs = runtime.run_action("verify", journal_id=args.journal_id, commands=commands, timeout=args.timeout)
        return {"journalId": args.journal_id, "executed": True, "commands": preview, "verificationRuns": runs}, 0 if runs and all(run["exitCode"] == 0 for run in runs) else 1
    if command in {"recovery-preview", "recover"}:
        preview = runtime.run_action("recovery-preview", journal_id=args.journal_id)
        if command == "recovery-preview" or not args.execute:
            return {"executed": False, **preview}, 0
        if not preview["allowed"]:
            return {"executed": False, "success": False, **preview}, 1
        result = runtime.run_action("recover", journal_id=args.journal_id)
        return {"executed": True, "preview": preview, **result}, 0 if result["success"] else 1
    if command == "protection":
        if args.protection_action == "add":
            return runtime.run_action("protect", path=args.path, auto_restore=args.auto_restore), 0
        if args.protection_action == "list":
            return runtime.run_action("protection-list"), 0
        return runtime.run_action("unprotect", rule_id=args.rule_id), 0
    if command == "memory":
        return runtime.run_action("scan-memory", targets=args.targets), 0
    raise ValueError("Unknown command")


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None, stderr: TextIO | None = None) -> int:
    args = parser().parse_args(argv)
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    if hasattr(stdout, "reconfigure"):
        stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        result, code = dispatch(OperationsRuntime(args.database), args)
        payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(payload, encoding="utf-8")
        else:
            stdout.write(payload)
        return code
    except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
        stderr.write(json.dumps({"error": str(exc)}, ensure_ascii=True) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
