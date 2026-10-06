#!/usr/bin/env python3
"""Lossless, UI-oriented evidence projection for the portable collector.

The collector deliberately stores a small, append-only schema.  The native
macOS application has a richer read model (sessions, a timeline, incidents,
runtime relationships and provider trust).  This module supplies that read
model on Windows and Linux without changing the collector or its SQLite
schema.  It is intentionally dependency free and never mutates its input.

``EvidenceProjector.project`` accepts either one snapshot dictionary or an
iterable of snapshots.  A snapshot may contain ``nativeEvents``,
``webEvents``, ``fileEvents``, ``connections`` and ``processes``.  Unknown
fields are retained in ``details`` rather than discarded.  Every projected
record has a conservative ``confidence`` value (``confirmed``, ``inferred``
or ``unknown``); the projector does not turn time proximity into confirmed
identity.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import json
import ntpath
import os
import posixpath
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import urlsplit


CONFIDENCE_RANK = {"unknown": 0, "inferred": 1, "confirmed": 2}
_MAX_TEXT = 2048


def _string(value: Any) -> Optional[str]:
    if value is None:
        return None
    value = str(value)
    return value if value else None


def _timestamp(value: Any) -> str:
    """Return a stable ISO timestamp while accepting epoch seconds/millis."""
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000:
            number /= 1000
        try:
            return _dt.datetime.fromtimestamp(number, _dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return ""
    if isinstance(value, str):
        value = value.strip()
        if value:
            return value
    return ""


def _epoch(value: str) -> float:
    if not value:
        return 0.0
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=parsed.tzinfo or _dt.timezone.utc).timestamp()
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _stable_id(*parts: Any) -> str:
    data = json.dumps(parts, ensure_ascii=True, separators=(",", ":"), default=str)
    return hashlib.sha256(data.encode("utf-8", "replace")).hexdigest()[:32]


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _confidence(value: Any, *, source: str = "", native: bool = False) -> str:
    value = str(value or "").lower()
    if value in CONFIDENCE_RANK:
        return value
    # Native adapters carry stable provider/session/turn IDs.  That is strong
    # identity evidence, but does not claim an operating-system process join.
    if native:
        return "confirmed"
    if any(name in source.lower() for name in ("polling", "inotify", "etw", "snapshot")):
        return "inferred"
    return "unknown"


def _event_text(event: Mapping[str, Any]) -> Optional[str]:
    for key in ("text", "summary", "command", "output", "result", "message", "path"):
        value = event.get(key)
        if value is not None:
            if isinstance(value, (dict, list)):
                try:
                    value = json.dumps(value, ensure_ascii=True, sort_keys=True)
                except (TypeError, ValueError):
                    value = str(value)
            value = str(value).strip()
            if value:
                return value[:_MAX_TEXT]
    return None


def _provider(event: Mapping[str, Any]) -> Optional[str]:
    provider = _string(event.get("provider") or event.get("agent"))
    if provider:
        return provider.lower()
    source = str(event.get("source") or "")
    if ":" in source and source.startswith(("agentreins-native:", "agentsight:")):
        return source.split(":", 1)[1].split("-", 1)[0].lower() or None
    return None


def _source(event: Mapping[str, Any], fallback: str) -> str:
    return str(event.get("source") or event.get("captureMethod") or fallback)


def _event_type(event: Mapping[str, Any], fallback: str = "observation") -> str:
    value = event.get("eventType") or event.get("type") or event.get("kind") or fallback
    value = str(value).lower().replace("-", "_")
    if value == "tool":
        return "tool_result" if event.get("op") == "result" else "tool_call"
    if value == "model":
        return "prompt" if event.get("op") == "prompt" else "response"
    aliases = {"toolresult": "tool_result", "networkconnection": "network"}
    return aliases.get(value, value)


def _iter_snapshots(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
    elif isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        for item in value:
            if isinstance(item, Mapping):
                yield item


def _host(value: Any) -> Optional[str]:
    text = str(value or "").strip().lower().rstrip(".")
    if not text or text in {"*", "*:*", "0.0.0.0:0", "[::]:0"}:
        return None
    try:
        if "://" in text:
            return urlsplit(text).hostname
        if text.startswith("["):
            return text[1:text.index("]")]
        if text.count(":") == 1:
            return text.rsplit(":", 1)[0]
        return text
    except ValueError:
        return None


def assess_destination(destination: Any) -> dict[str, Any]:
    """Port of NetworkDestinationSecurity; hostname suffixes require a dot boundary."""
    host = _host(destination)
    kind, attention = "unknown", True
    reason = "The destination identity is not available."
    if host:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        matches = lambda domains: any(host == name or host.endswith("." + name) for name in domains)
        if host == "localhost" or (address and (address.is_loopback or address.is_private or address.is_link_local)):
            kind, attention, reason = "localInfrastructure", False, "Local endpoint; it does not identify the final external destination."
        elif matches(("openrouter.ai", "portkey.ai", "helicone.ai", "litellm.ai", "requesty.ai", "withmartian.com", "braintrust.dev", "ai-gateway.vercel.sh", "gateway.ai.cloudflare.com")):
            kind, reason = "modelRelay", "Model intermediary; the final upstream model is not independently verified."
        elif matches(("chatgpt.com", "openai.com", "anthropic.com", "claude.ai", "deepseek.com", "mistral.ai", "groq.com", "together.ai", "cohere.com", "x.ai", "fireworks.ai", "perplexity.ai", "moonshot.ai", "siliconflow.cn", "dashscope.aliyuncs.com", "gemini.google.com", "grok.com", "generativelanguage.googleapis.com", "aiplatform.googleapis.com", "openai.azure.com")) or (".bedrock-runtime." in host and host.endswith(".amazonaws.com")):
            kind, attention, reason = "modelProvider", False, "Recognized model-service hostname; model identity and payload contents remain unverified."
        elif matches(("github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "npmjs.org", "npmjs.com", "pypi.org", "crates.io", "stackoverflow.com")):
            kind, reason = "developerService", "Developer content crosses an external trust boundary."
        elif matches(("sentry.io", "segment.io", "datadoghq.com", "cline.bot")):
            kind, attention, reason = "telemetry", False, "Recognized telemetry hostname; data disclosure requires separate evidence."
        elif address:
            reason = "Only an IP address was observed; the destination domain remains unknown."
        else:
            kind, reason = "externalContent", "External content source; no trust guarantee is inferred."
    return {"destination": host, "kind": kind, "needsAttention": attention, "reason": reason,
            "identityStatus": "unverified", "confidence": "inferred" if host else "unknown"}


def assess_tool(name: Any, command: Any = None) -> dict[str, str]:
    """Describe capabilities; a powerful tool is not proof of an incident."""
    text = f"{name or ''} {command or ''}".lower()
    kind = "mcp" if any(value in text for value in ("mcp__", "mcp-", "mcp server")) else "skill" if "skill" in text else "tool"
    if any(value in text for value in ("bash", "shell", "terminal", "exec", "powershell", "cmd.exe")):
        risk, capability = "high", "Arbitrary command execution"
    elif any(value in text for value in ("delete", "remove", "write", "edit", "patch", "move", "rename")):
        risk, capability = "high", "Filesystem mutation"
    elif kind in {"mcp", "skill"}:
        risk, capability = "medium", "External integration" if kind == "mcp" else "Instruction extension"
    elif any(value in text for value in ("fetch", "web", "http", "browser", "search")):
        risk, capability = "medium", "Network access"
    elif any(value in text for value in ("read", "open", "memory", "retrieve", "load")):
        risk, capability = "medium", "Local data access"
    elif not name or name == "unknown_tool":
        risk, capability = "unknown", "Unidentified capability"
    else:
        risk, capability = "low", "Limited observed action"
    return {"kind": kind, "risk": risk, "capability": capability}


def _tool_status(raw: Mapping[str, Any], result: bool = False) -> str:
    action = str(raw.get("status") or raw.get("action") or "").lower()
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), Mapping) else {}
    exit_code = raw.get("exit_code", raw.get("exitCode", metadata.get("exit_code", metadata.get("exitCode"))))
    text = str(raw.get("text") or raw.get("output") or raw.get("result") or "")
    if exit_code is None:
        match = re.search(r'(?:exit[_ ]code[\s"\x27:]*|exited with code\s+)(-?\d+)\b', text, re.I)
        exit_code = int(match.group(1)) if match else None
    if action in {"failed", "error", "denied", "cancelled", "canceled", "timeout", "timed_out"} or raw.get("is_error") is True or (exit_code is not None and str(exit_code) != "0"):
        return "failed"
    if action in {"running", "pending", "in_progress"} or re.search(r"\b(?:script|process|command) (?:is |still )?running\b", text, re.I):
        return "running"
    if exit_code is not None or action in {"completed", "complete", "done", "success", "succeeded"}:
        return "completed"
    return "result_received" if result else "requested"


def discover_git_remotes(workspace: Any) -> list[dict[str, Any]]:
    """Read remote URLs from a workspace's .git/config (including worktrees)."""
    root = Path(str(workspace or "")).expanduser()
    if not root.is_dir():
        root = root.parent
    for _ in range(10):
        dotgit = root / ".git"
        config = dotgit / "config" if dotgit.is_dir() else dotgit
        if dotgit.is_file():
            try:
                pointer = dotgit.read_text(encoding="utf-8", errors="replace").strip()
                match = re.match(r"gitdir:\s*(.+)", pointer, re.I)
                if match:
                    gitdir = Path(match.group(1)).expanduser()
                    if not gitdir.is_absolute():
                        gitdir = (root / gitdir).resolve()
                    config = gitdir / "config"
                    common = gitdir / "commondir"
                    if not config.exists() and common.is_file():
                        common_path = Path(common.read_text(encoding="utf-8", errors="replace").strip())
                        config = (common_path if common_path.is_absolute() else gitdir / common_path) / "config"
            except OSError:
                pass
        try:
            text = config.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if text:
            section: Optional[str] = None
            result: list[dict[str, Any]] = []
            for line in text.splitlines():
                section_match = re.match(r"\s*\[remote\s+\"([^\"]+)\"\]", line, re.I)
                if section_match:
                    section = section_match.group(1)
                    continue
                if line.lstrip().startswith("["):
                    section = None
                match = re.match(r"\s*url\s*=\s*(\S+)", line, re.I)
                if match and section:
                    value = match.group(1)
                    host = _host(value) if "://" in value else _host("https://" + value.split("@", 1)[-1].split(":", 1)[0])
                    if not host and "@" in value:
                        host = value.split("@", 1)[1].split(":", 1)[0].lower()
                    result.append({"remote": section, "host": host, "url": re.sub(r"//[^/@:]+:[^/@]+@", "//[REDACTED]@", value), "source": "git-config", "confidence": "confirmed", "evidenceType": "configuration"})
            return result
        parent = root.parent
        if parent == root:
            break
        root = parent
    return []


def _sensitive_findings(text: Any, source: str) -> list[dict[str, Any]]:
    value = str(text or "")
    patterns = (("privateKey", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical"),
                ("apiCredential", r"(?:sk-[A-Za-z0-9_-]{16,}|(?:api[_ -]?key|access[_ -]?token|secret)\s*[:=]\s*[^\s\"']{12,})", "critical"),
                ("password", r"(?:password|passwd|pwd|密码)\s*[:=]\s*[^\s\"']{6,}", "high"),
                ("email", r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "medium"))
    result = []
    for category, expression, severity in patterns:
        for match in re.finditer(expression, value, re.I):
            result.append({"category": category, "source": source, "severity": severity,
                           "evidence": "[REDACTED]", "confidence": "confirmed", "retentionProven": False})
    return result


class EvidenceProjector:
    """Build the portable equivalent of the native Operations Center read model."""

    def __init__(self, max_events: int = 5_000) -> None:
        self.max_events = max(1, int(max_events))
        self._history: dict[str, dict[str, Any]] = {}
        self._latest_processes: list[dict[str, Any]] = []
        self._latest_connections: list[dict[str, Any]] = []

    def clear(self) -> None:
        self._history.clear()
        self._latest_processes.clear()
        self._latest_connections.clear()

    def project(self, snapshots: Any) -> dict[str, Any]:
        all_snapshots = list(_iter_snapshots(snapshots))
        events: list[dict[str, Any]] = []
        for index, snapshot in enumerate(all_snapshots):
            snap_ts = _timestamp(snapshot.get("timestamp"))
            if "processes" in snapshot:
                self._latest_processes = self._processes(snapshot.get("processes"), snap_ts, index)
            if "connections" in snapshot:
                self._latest_connections = self._connections(snapshot.get("connections"), snap_ts, index, self._latest_processes)
                events.extend(self._latest_connections)
            for key, fallback in (("nativeEvents", "native"), ("webEvents", "web"), ("events", "event")):
                rows = snapshot.get(key)
                if isinstance(rows, list):
                    events.extend(self._events(rows, fallback, snap_ts, index))
            # Proxy logs are opt-in: the portable collector does not search
            # proxy application directories. Callers must explicitly provide
            # normalized rows under proxyEvents/proxyLogs.
            proxy_rows = snapshot.get("proxyEvents") or snapshot.get("proxyLogs")
            if isinstance(proxy_rows, list):
                for row in self._events(proxy_rows, "proxy-log", snap_ts, index):
                    row["evidenceType"], row["observationConfidence"] = "proxy_destination", "confirmed"
                    events.append(row)
            events.extend(self._file_events(snapshot.get("fileEvents"), snap_ts, index))
        # Last-write-wins is useful for repeated watch snapshots while keeping
        # distinct records with the same provider IDs from collapsing.
        for event in events:
            self._history[str(event["id"])] = event
        events = sorted(self._history.values(), key=lambda row: (_epoch(str(row.get("timestamp") or "")), str(row["id"])))
        if len(events) > self.max_events:
            events = events[-self.max_events :]
        self._history = {row["id"]: row for row in events}
        tools = self._tool_calls(events)
        intents = self._tool_intents(tools)
        sessions = self._sessions(events, tools)
        timeline = self._timeline(events + intents, [], self._latest_processes)
        incidents = self._incidents(events, timeline)
        git_remotes: list[dict[str, Any]] = []
        sensitive: list[dict[str, Any]] = []
        workspaces: set[str] = set()
        for event in events:
            details = event.get("details") if isinstance(event.get("details"), Mapping) else {}
            metadata = details.get("metadata") if isinstance(details.get("metadata"), Mapping) else {}
            workspace = details.get("workspace") or metadata.get("workspace") or details.get("cwd")
            if workspace:
                workspaces.add(str(workspace))
            sensitive.extend(_sensitive_findings(event.get("summary") or _event_text(details), f"event:{event['id']}"))
        for workspace in workspaces:
            git_remotes.extend(discover_git_remotes(workspace))
        config_endpoints: list[dict[str, Any]] = []
        try:
            from .provider_config import discover_defaults
        except ImportError:
            try:
                from provider_config import discover_defaults
            except ImportError:
                discover_defaults = None
        if discover_defaults:
            try:
                config_endpoints = discover_defaults()
            except Exception:
                config_endpoints = []
        return {
            "schemaVersion": 1,
            "sessions": sessions,
            "timeline": timeline,
            "files": [event for event in events if event.get("kind") == "file"],
            "toolCalls": tools,
            "incidents": incidents,
            "providerTrust": self._provider_trust(events + intents),
            "runtimeGraph": self._runtime_graph(self._latest_processes),
            "contextReports": self._context_reports(events),
            "gitRemotes": git_remotes,
            "configuredEndpoints": config_endpoints,
            "providerConfig": config_endpoints,
            "sensitiveExposure": sensitive[-500:],
            "summary": {
                "eventCount": len(events), "timelineCount": len(timeline),
                "sessionCount": len(sessions), "incidentCount": len(incidents),
                "providerCount": len(self._provider_names(events)),
                "toolCount": len(tools),
                "confidence": self._overall_confidence(events),
            },
        }

    def _events(self, rows: Any, fallback: str, snap_ts: str, snapshot_index: int) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        if not isinstance(rows, list):
            return result
        for row_index, raw in enumerate(rows):
            if not isinstance(raw, Mapping):
                continue
            source = _source(raw, fallback)
            native = fallback == "native" or source.startswith(("agentreins-native:", "agentsight:"))
            timestamp = _timestamp(raw.get("timestamp") or raw.get("observedAt") or raw.get("ts") or snap_ts)
            event_type = _event_type(raw)
            session = _string(raw.get("sessionId") or raw.get("session_id"))
            turn = _string(raw.get("turnId") or raw.get("turn_id"))
            tool_call = _string(raw.get("toolCallId") or raw.get("tool_call_id"))
            event_id = _string(raw.get("eventId") or raw.get("event_id") or raw.get("id")) or _stable_id(source, timestamp, json.dumps(_jsonable(raw), sort_keys=True))
            provider = _provider(raw)
            confidence = _confidence(raw.get("attributionConfidence") or raw.get("confidence"), source=source,
                                     native=bool(native and session))
            details = _jsonable(dict(raw))
            result.append({
                "id": _stable_id(provider, session, source, event_id), "eventId": event_id, "timestamp": timestamp, "kind": event_type,
                "title": self._title(event_type, raw), "summary": _event_text(raw),
                "provider": provider, "source": source, "sessionId": session,
                "turnId": turn, "toolCallId": tool_call, "confidence": confidence,
                "attributionMethod": "Recorded native session identifiers" if native and session else "Source record; no native identity join",
                "evidenceType": "transcript" if native else "observation",
                "details": details,
            })
        return result

    def _file_events(self, rows: Any, snap_ts: str, snapshot_index: int) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        if not isinstance(rows, list):
            return result
        for row_index, raw in enumerate(rows):
            if not isinstance(raw, Mapping):
                continue
            source = _source(raw, "file-polling")
            timestamp = _timestamp(raw.get("timestamp") or raw.get("observedAt") or snap_ts)
            path = _string(raw.get("path"))
            action = str(raw.get("action") or "changed").lower()
            context = raw.get("context") if isinstance(raw.get("context"), Mapping) else raw
            session = _string(context.get("sessionId") or context.get("session_id"))
            turn = _string(context.get("turnId") or context.get("turn_id"))
            tool_call = _string(context.get("toolCallId") or context.get("tool_call_id"))
            event_id = _string(raw.get("eventId") or raw.get("id")) or _stable_id("file", source, timestamp, path, action)
            result.append({
                "id": event_id, "timestamp": timestamp, "kind": "file",
                "title": f"File {action}", "summary": path, "provider": _provider(raw),
                "source": source, "sessionId": session, "turnId": turn,
                "toolCallId": tool_call, "confidence": "inferred" if session else "unknown",
                "observationConfidence": "confirmed", "evidenceType": "observation",
                "attributionMethod": "Stored evidence link" if session else "File change observed; originating agent unknown",
                "details": _jsonable(dict(raw)),
            })
        return result

    def _processes(self, rows: Any, snap_ts: str, snapshot_index: int) -> list[dict[str, Any]]:
        result = []
        if not isinstance(rows, list):
            return result
        for raw in rows:
            if not isinstance(raw, Mapping):
                continue
            pid = _string(raw.get("pid"))
            if not pid:
                continue
            result.append({"pid": pid, "ppid": _string(raw.get("ppid")) or "0", "command": _string(raw.get("command")) or "",
                           "executable": _string(raw.get("executable")) or "", "agent": _string(raw.get("agent")),
                           "timestamp": snap_ts, "confidence": _confidence(raw.get("confidence"), source="process-polling")})
        by_pid = {row["pid"]: row for row in result}
        collector = {row["pid"] for row in result if row["pid"] == str(os.getpid()) or re.search(r"(?:^|[\\/\s])agentreins(?:_desktop|_portable)?(?:\.exe|\.py|\s|$)", row["command"], re.I)}
        for row in result:
            ancestors, parent = set(), row
            while parent and parent["pid"] not in ancestors:
                ancestors.add(parent["pid"])
                if not row["agent"] and parent.get("agent"):
                    row["agent"] = parent["agent"]
                parent = by_pid.get(parent["ppid"])
            row["_excluded"] = bool(ancestors & collector)
        return [row for row in result if not row.pop("_excluded")]

    def _connections(self, rows: Any, snap_ts: str, snapshot_index: int, processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result = []
        if not isinstance(rows, list):
            return result
        by_pid = {row["pid"]: row for row in processes}
        for index, raw in enumerate(rows):
            if not isinstance(raw, Mapping):
                continue
            pid = _string(raw.get("pid"))
            timestamp = _timestamp(raw.get("timestamp") or raw.get("observedAt") or snap_ts)
            source = _source(raw, "network-snapshot")
            owner = by_pid.get(pid, {}).get("agent")
            result.append({"id": _string(raw.get("id") or raw.get("eventId")) or _stable_id("network", timestamp, pid, raw.get("local"), raw.get("remote")),
                           "timestamp": timestamp, "kind": "network", "title": "Network connection",
                           "summary": f"{raw.get('local', '')} → {raw.get('remote', '')}".strip(" →"),
                           "provider": owner, "source": source, "sessionId": None,
                           "turnId": None, "toolCallId": None, "confidence": "inferred" if owner else "unknown",
                           "observationConfidence": "confirmed" if pid else "inferred", "evidenceType": "observation",
                           "destination": assess_destination(raw.get("remoteDomain") or raw.get("remote")),
                           "details": _jsonable(dict(raw)), "pid": pid})
        return result

    @staticmethod
    def _title(event_type: str, raw: Mapping[str, Any]) -> str:
        names = {"prompt": "Prompt", "response": "Agent response", "reasoning": "Agent reasoning", "tool_call": "Tool call", "tool_result": "Tool result", "context": "Session context", "file": "File change", "network": "Network activity"}
        title = names.get(event_type, event_type.replace("_", " ").title())
        tool = _string(raw.get("toolName") or raw.get("tool_name"))
        return f"{title}: {tool}" if tool and event_type in {"tool_call", "tool_result"} else title

    def _sessions(self, events: list[dict[str, Any]], tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            if event.get("sessionId"):
                groups[(event.get("provider"), str(event["sessionId"]))].append(event)
        result = []
        for (provider, session_id), rows in groups.items():
            rows = sorted(rows, key=lambda row: _epoch(str(row.get("timestamp") or "")))
            providers = sorted({str(row["provider"]) for row in rows if row.get("provider")})
            tool_names = sorted({str(row["details"].get("toolName")) for row in rows if isinstance(row.get("details"), Mapping) and row["details"].get("toolName")})
            result.append({"id": session_id, "key": _stable_id(provider, session_id), "provider": provider, "providers": providers,
                           "firstSeen": rows[0].get("timestamp"), "lastSeen": rows[-1].get("timestamp"),
                           "eventCount": len(rows), "toolCount": len({row.get("toolCallId") for row in rows if row.get("toolCallId")}),
                           "tools": tool_names, "status": self._session_status(rows), "confidence": self._overall_confidence(rows),
                           "turnCount": len({row["turnId"] for row in rows if row.get("turnId")}),
                           "models": sorted({str(row["details"]["model"]) for row in rows if row["details"].get("model")}),
                           **self._token_totals(rows)})
        return sorted(result, key=lambda row: _epoch(str(row.get("lastSeen") or "")), reverse=True)

    @staticmethod
    def _session_status(rows: list[dict[str, Any]]) -> str:
        last = rows[-1] if rows else {}
        details = last.get("details") if isinstance(last.get("details"), Mapping) else {}
        status = str(details.get("status") or details.get("action") or "").lower()
        if last.get("kind") == "tool_result" and any(word in status for word in ("fail", "error")):
            return "failed"
        if last.get("kind") in {"turn_completed", "session_completed"} or status in {"turn_completed", "session_completed"}:
            return "completed"
        if last.get("kind") == "response":
            return "response_received"
        return "observed"

    def _timeline(self, events: list[dict[str, Any]], connections: list[dict[str, Any]], processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        timeline = list(events)
        # Process/network records are observations, not fabricated agent turns.
        timeline.extend(connections)
        return sorted(timeline, key=lambda row: (_epoch(str(row.get("timestamp") or "")), str(row["id"])), reverse=True)

    @staticmethod
    def _token_totals(events: list[dict[str, Any]]) -> dict[str, Optional[int]]:
        totals: dict[str, Optional[int]] = {key: None for key in ("inputTokens", "outputTokens", "cachedTokens", "reasoningTokens")}
        aliases = {"inputTokens": ("inputTokens", "input_tokens"), "outputTokens": ("outputTokens", "output_tokens"),
                   "cachedTokens": ("cachedTokens", "cached_tokens", "cache_read_input_tokens"),
                   "reasoningTokens": ("reasoningTokens", "reasoning_tokens")}
        for event in events:
            raw = event.get("details", {})
            metadata = raw.get("metadata") if isinstance(raw.get("metadata"), Mapping) else {}
            usage = raw.get("usage") or metadata.get("usage") or {}
            usage = usage if isinstance(usage, Mapping) else {}
            for key, names in aliases.items():
                value = next((source[name] for source in (raw, usage, metadata) for name in names if source.get(name) is not None), None)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    totals[key] = (totals[key] or 0) + value
        return totals

    @staticmethod
    def _tool_calls(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            if event["kind"] in {"tool_call", "tool_result", "upload"}:
                # Anonymous calls must not all collapse into one row.
                groups[(event.get("provider"), event.get("sessionId"), event.get("toolCallId") or event["id"])].append(event)
        result = []
        for (provider, session, call_id), rows in groups.items():
            rows.sort(key=lambda row: (_epoch(row["timestamp"]), row["kind"] == "tool_result"))
            calls = [row for row in rows if row["kind"] == "tool_call"]
            results = [row for row in rows if row["kind"] in {"tool_result", "upload"}]
            start, end = calls[0] if calls else rows[0], results[-1] if results else rows[-1]
            command = start["details"].get("command") or start["details"].get("arguments")
            if isinstance(command, (dict, list)):
                command = json.dumps(command, ensure_ascii=True)
            name = next((row["details"].get("toolName") or row["details"].get("tool_name") for row in calls + rows
                         if row["details"].get("toolName") or row["details"].get("tool_name")), "unknown_tool")
            start_epoch, end_epoch = _epoch(start["timestamp"]), _epoch(end["timestamp"])
            result.append({"id": _stable_id(provider, session, call_id), "toolCallId": call_id,
                           "sessionId": session, "turnId": start.get("turnId") or end.get("turnId"), "provider": provider,
                           "toolName": name, "command": command, "result": _event_text(end["details"]) if results else None,
                           "status": _tool_status(end["details"], bool(results)), "firstSeen": start["timestamp"],
                           "lastSeen": end["timestamp"], "durationMs": max(0, round((end_epoch - start_epoch) * 1000)) if results and start_epoch and end_epoch else None,
                           "confidence": EvidenceProjector._overall_confidence(rows), "security": assess_tool(name, command),
                           "eventIds": [row["id"] for row in rows], "details": dict(start["details"])})
        return sorted(result, key=lambda row: _epoch(row["lastSeen"]), reverse=True)

    @staticmethod
    def _tool_intents(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        output = []
        for tool in tools:
            command = str(tool.get("command") or "")
            raw = tool.get("details", {})
            metadata = raw.get("metadata") if isinstance(raw.get("metadata"), Mapping) else {}
            workspace = str(raw.get("cwd") or raw.get("workspace") or metadata.get("cwd") or "")
            payload = {}
            try:
                value = json.loads(command)
                if isinstance(value, Mapping):
                    payload = value
                    workspace = str(payload.get("cwd") or payload.get("workdir") or workspace)
            except (ValueError, TypeError):
                pass
            descriptors = []
            for url in dict.fromkeys(re.findall(r'https?://[^\s\\"\x27<>)}\]]+', command, re.I)):
                destination = assess_destination(url.rstrip(",.;"))
                if destination["destination"]:
                    descriptors.append(("network", "connect", destination["destination"], None, destination))
            patches = re.findall(r"^\*\*\* (Add|Update|Delete) File:\s*([^\r\n]+)", command, re.M)
            paths = [(operation.lower(), path) for operation, path in patches]
            if not paths:
                path = payload.get("file_path") or payload.get("filePath") or payload.get("path")
                name = str(tool["toolName"]).lower()
                if isinstance(path, str):
                    operation = next((op for terms, op in ((('read', 'open', 'get'), 'read'), (('delete', 'remove'), 'delete'),
                                      (('write', 'create'), 'write'), (('edit', 'replace', 'patch'), 'update')) if any(term in name for term in terms)), None)
                    if operation:
                        paths.append((operation, path))
            for operation, path in paths:
                path_module = ntpath if ntpath.splitdrive(path)[0] or ntpath.splitdrive(workspace)[0] else posixpath
                path = path_module.normpath(path_module.join(workspace, path)) if workspace else path_module.normpath(path)
                descriptors.append(("file", operation, path, None, None))
            for index, (kind, action, value, related, destination) in enumerate(descriptors):
                row = {"id": _stable_id(tool["id"], "intent", index), "timestamp": tool["firstSeen"], "kind": kind,
                       "title": f"Requested {kind} {action}", "summary": value, "provider": tool["provider"],
                       "source": "tool-intent", "sessionId": tool["sessionId"], "turnId": tool["turnId"],
                       "toolCallId": tool["toolCallId"], "confidence": tool["confidence"], "evidenceType": "intent",
                       "status": tool["status"], "details": {"action": action, "path" if kind == "file" else "remoteDomain": value,
                       "toolName": tool["toolName"], "command": command, "eventIds": tool["eventIds"],
                       "effectVerified": False}}
                if destination:
                    row["destination"] = destination
                output.append(row)
        return output

    @staticmethod
    def _context_reports(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            if event.get("sessionId"):
                groups[(event.get("provider"), event["sessionId"], event.get("turnId"))].append(event)
        output = []
        for (provider, session, turn), rows in groups.items():
            prompts, responses, memory, ssh, context, attachments, instructions = [], [], [], [], [], [], []
            for row in rows:
                if row["kind"] == "prompt":
                    prompts.append(row["id"])
                elif row["kind"] == "response":
                    responses.append(row["id"])
                elif row["kind"] == "context":
                    context.append(row["id"])
                raw = row["details"]
                text = " ".join(str(raw.get(key) or "") for key in ("command", "path", "toolName"))
                normalized = text.replace("\\", "/").lower()
                if re.search(r"(?:^|[/\s])(?:memory|agents|claude|user|identity|soul)\.md\b|/agent-memory/|/knowledge/memory/", normalized):
                    memory.append({"eventId": row["id"], "path": raw.get("path"), "confidence": row["confidence"], "kind": "memory_access"})
                if re.search(r"\b(?:ssh|scp|sftp|rsync)(?:\.exe)?\s", text, re.I):
                    destination = EvidenceProjector._ssh_destination(text)
                    ssh.append({"eventId": row["id"], "command": text[:_MAX_TEXT], "destination": destination, "confidence": row["confidence"], "status": "requested"})
                if any(term in text.lower() for term in ("skill.md", "agent policy", "developer instruction")):
                    instructions.append({"eventId": row["id"], "kind": "instruction_context", "confidence": row["confidence"]})
                if any(term in text.lower() for term in ("attachment", "image", "screenshot")):
                    attachments.append({"eventId": row["id"], "kind": "attachment_reference", "confidence": row["confidence"]})
            output.append({"id": _stable_id(provider, session, turn), "provider": provider, "sessionId": session, "turnId": turn,
                           "promptEventIds": prompts, "responseEventIds": responses, "contextEventIds": context,
                           "memoryEvidence": memory, "sshEvidence": ssh, "instructionEvidence": instructions, "attachmentEvidence": attachments,
                           "models": sorted({str(row["details"]["model"]) for row in rows if row["details"].get("model")}),
                           "confidence": EvidenceProjector._overall_confidence(rows), **EvidenceProjector._token_totals(rows)})
        return output

    @staticmethod
    def _ssh_destination(command: str) -> Optional[dict[str, Any]]:
        match = re.search(r"\b(?:ssh|scp|sftp|rsync)(?:\.exe)?\b(?:\s+-[^\s]+(?:\s+[^\s-]+)?)*\s+(?:[^\s@:/]+@)?([^\s:/]+)", command, re.I)
        if not match:
            return None
        host = match.group(1).lower()
        port = int(re.search(r"(?:^|\s)-[Pp]\s*(\d+)", command).group(1)) if re.search(r"(?:^|\s)-[Pp]\s*(\d+)", command) else 22
        return {"host": host, "port": port, "transport": "ssh", "observed": False, "confidence": "inferred"}

    def _incidents(self, events: list[dict[str, Any]], timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        for event in timeline:
            details = event.get("details") if isinstance(event.get("details"), Mapping) else {}
            text = str(details.get("command") or "").lower()
            kind = str(event.get("kind") or "")
            reason = None
            severity = "info"
            if details.get("ruleId") and details.get("severity") in {"critical", "high", "medium"}:
                reason, severity = str(details.get("message") or details["ruleId"]), details["severity"]
            elif kind == "tool_result" and _tool_status(details, True) == "failed":
                reason, severity = "Tool execution failed", "medium"
            elif kind == "file" and str(details.get("action") or "").lower() in {"delete", "deleted", "removed"} and event.get("evidenceType") != "intent":
                reason, severity = "File deletion observed", "medium"
            elif kind == "tool_call" and (
                re.search(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b", text)
                or re.search(r"\bgit\s+push\b[^\n]*(?:--force(?:\s|$)|\s-f(?:\s|$))", text)
                or re.search(r"\brm\s+-[a-z]*r[a-z]*f\b|\brm\s+-[a-z]*f[a-z]*r\b", text)
                or re.search(r"\bremove-item\b[^\n]*-recurse\b[^\n]*-force\b", text)
            ):
                reason, severity = "High-risk tool activity", "high"
            if reason:
                candidates.append({"id": _stable_id("incident", event.get("id"), reason), "title": reason, "severity": severity,
                                   "timestamp": event.get("timestamp"), "sessionId": event.get("sessionId"), "turnId": event.get("turnId"),
                                   "toolCallId": event.get("toolCallId"), "eventIds": [event.get("id")], "confidence": event.get("confidence", "unknown"),
                                   "status": "observed", "summary": event.get("summary")})
        # Native tool IDs group related rule signals, matching the native
        # incident view. Unrelated operations never merge only by timestamp.
        grouped: dict[tuple, dict[str, Any]] = {}
        for incident in candidates:
            key = (incident["sessionId"], incident["toolCallId"]) if incident["toolCallId"] else (incident["id"],)
            existing = grouped.get(key)
            if existing and abs(_epoch(str(existing["timestamp"] or "")) - _epoch(str(incident["timestamp"] or ""))) <= 5:
                existing["eventIds"].extend(incident["eventIds"])
                existing.setdefault("reasons", [existing["title"]]).append(incident["title"])
                ranks = {"info": 0, "medium": 1, "high": 2, "critical": 3}
                if ranks[incident["severity"]] > ranks[existing["severity"]]:
                    existing["severity"], existing["title"] = incident["severity"], incident["title"]
            else:
                grouped[key] = incident
        return list(grouped.values())

    @staticmethod
    def _provider_names(events: list[dict[str, Any]]) -> set[str]:
        return {str(event["provider"]) for event in events if event.get("provider")}

    def _provider_trust(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            if event.get("provider"):
                groups[str(event["provider"])].append(event)
        result = []
        for provider, rows in groups.items():
            confirmed = sum(1 for row in rows if row.get("confidence") == "confirmed")
            inferred = sum(1 for row in rows if row.get("confidence") == "inferred")
            routes = {row["destination"]["destination"]: row["destination"] for row in rows if row.get("destination") and row["destination"].get("destination")}
            models = sorted({str(row["details"]["model"]) for row in rows if row["details"].get("model")})
            relay = any(route["kind"] == "modelRelay" for route in routes.values())
            official = any(route["kind"] == "modelProvider" for route in routes.values())
            result.append({"provider": provider, "eventCount": len(rows), "confirmedCount": confirmed,
                           "inferredCount": inferred, "unknownCount": len(rows) - confirmed - inferred,
                           "routes": list(routes.values()), "models": models,
                           "sources": sorted({str(row["source"]) for row in rows}),
                           "identityStatus": "unverified", "level": "relay_observed" if relay else "recognized_route" if official else "unverified",
                           "reason": "Agent transcript identity does not authenticate the upstream model.",
                           "confidence": "confirmed" if confirmed == len(rows) else "inferred" if confirmed or inferred else "unknown"})
        return sorted(result, key=lambda row: row["provider"])

    @staticmethod
    def _overall_confidence(events: list[dict[str, Any]]) -> str:
        if not events:
            return "unknown"
        # Aggregate at the weakest evidence level. Averaging can otherwise
        # silently promote an unknown event into a confirmed claim.
        rank = min(CONFIDENCE_RANK.get(str(row.get("confidence")), 0) for row in events)
        return ("unknown", "inferred", "confirmed")[rank]

    @staticmethod
    def _runtime_graph(processes: list[dict[str, Any]]) -> dict[str, Any]:
        ids = {row["pid"] for row in processes}
        nodes = []
        for row in processes:
            node = {key: row.get(key) for key in ("pid", "ppid", "command", "executable", "agent", "confidence")}
            text = f"{row.get('command', '')} {row.get('executable', '')}".lower()
            if any(name in text for name in ("mcp", "modelcontextprotocol")):
                component, responsibility = "MCP", "External tool server"
            elif any(name in text for name in ("node_repl", "node-repl", "js_repl")):
                component, responsibility = "Node REPL", "Persistent JavaScript execution"
            elif re.search(r"(?:^|[\\/\s])(?:bash|sh|zsh|pwsh|powershell|cmd)(?:\.exe)?(?:\s|$)", text):
                component, responsibility = "Shell", "Command execution"
            elif any(name in text for name in ("sqlite", "storage", "database")):
                component, responsibility = "Storage", "State and evidence persistence"
            elif any(name in text for name in ("networkservice", "network-service", "proxy", "curl", "wget")):
                component, responsibility = "Network", "Network transport or proxy"
            elif row.get("agent"):
                component, responsibility = "Agent Core", "Agent runtime (inferred from process identity)"
            else:
                component, responsibility = "Process", "Unclassified process"
            node.update(id=f"process:{row['pid']}", component=component, responsibility=responsibility)
            nodes.append(node)
        edges = [{"id": _stable_id("parent", row["ppid"], row["pid"]), "sourcePID": row["ppid"], "targetPID": row["pid"], "kind": "processParent", "confidence": "confirmed"}
                 for row in processes if row.get("ppid") in ids and row.get("pid") != row.get("ppid")]
        return {"nodes": nodes, "relationships": edges}


def project_evidence(snapshots: Any, *, max_events: int = 5_000) -> dict[str, Any]:
    """Convenience wrapper used by the desktop shell and integrations."""
    return EvidenceProjector(max_events=max_events).project(snapshots)


def project_database(path: os.PathLike[str] | str, *, limit: int = 5_000) -> dict[str, Any]:
    """Project existing portable SQLite evidence without writing to it."""
    database = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    database.row_factory = sqlite3.Row
    try:
        database.execute("BEGIN")
        tables = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        snapshots = []
        snapshot_rows = database.execute("SELECT payload FROM snapshots ORDER BY id DESC LIMIT ?", (min(64, max(1, int(limit))),)) if "snapshots" in tables else []
        for row in snapshot_rows:
            try:
                value = json.loads(row[0])
            except (TypeError, ValueError):
                continue
            if isinstance(value, Mapping):
                snapshots.append(value)
        # Web/file rows can predate snapshots or be collected between ticks.
        extra = {"nativeEvents": [], "webEvents": [], "fileEvents": []}
        event_rows = database.execute("SELECT payload FROM web_events ORDER BY id DESC LIMIT ?", (max(1, int(limit)),)) if "web_events" in tables else []
        for row in event_rows:
            try:
                value = json.loads(row[0])
            except (TypeError, ValueError):
                continue
            if isinstance(value, Mapping):
                extra["webEvents"].append(value)
        if "file_events" in tables:
            for row in database.execute("SELECT * FROM file_events ORDER BY id DESC LIMIT ?", (max(1, int(limit)),)):
                value = dict(row)
                db_id = value.pop("id", None)
                try:
                    value["details"] = json.loads(value.get("details") or "{}")
                except (TypeError, ValueError):
                    value["details"] = {}
                if "evidence_links" in tables:
                    links = database.execute("SELECT DISTINCT session_id,turn_id,tool_call_id,confidence FROM evidence_links WHERE source_kind='file_event' AND source_id=?", (str(db_id),)).fetchall()
                    if len(links) == 1:
                        value["context"] = dict(links[0])
                        value["confidence"] = "inferred"
                extra["fileEvents"].append(value)
        return project_evidence([*reversed(snapshots), extra], max_events=limit)
    finally:
        database.close()


__all__ = ["EvidenceProjector", "project_evidence", "project_database", "assess_destination", "assess_tool"]
