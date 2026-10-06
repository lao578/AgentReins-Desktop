#!/usr/bin/env python3
"""Read-only native session adapters for local AI coding agents.

The macOS console has provider-specific adapters for Codex, Claude, Qoder,
WorkBuddy, and Cursor.  Windows and Linux use the portable collector, so this
module provides the same small, normalized event boundary without depending on
an SDK or on private network traffic.  Adapters only read local session
transcripts that an agent has already written; they never read credentials or
modify the source files.

The public output is intentionally close to the browser Native-Messaging
schema consumed by :class:`agentreins_portable.EvidenceStore`::

    {"schemaVersion": 2, "eventId": "...", "eventType": "prompt|response|
     reasoning|tool_call|tool_result|context", "provider": "codex", ...}

Unknown rows are retained as ``diagnostic`` events only when they carry a
stable id.  A malformed JSONL row is skipped, allowing a live writer's partial
last line to be retried on the next poll.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import platform
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional


ADAPTER_VERSION = "native-0.1.0"
MAX_TEXT = 512_000
MAX_FILES_PER_POLL = 32
MAX_BYTES_PER_FILE = 512 * 1024


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _text(value: Any) -> Optional[str]:
    """Extract displayable text from common transcript content shapes."""
    if isinstance(value, str):
        return value[:MAX_TEXT] or None
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        parts = [part for item in value if (part := _text(item))]
        return "\n".join(parts)[:MAX_TEXT] or None
    if isinstance(value, Mapping):
        for key in ("text", "content", "summary", "thinking", "output", "result", "message"):
            if key in value:
                result = _text(value[key])
                if result:
                    return result
    return None


def _json(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True)[:MAX_TEXT]
    except (TypeError, ValueError):
        return _text(value)


def _timestamp(value: Any) -> str:
    if isinstance(value, (int, float)):
        # Some providers write milliseconds, others seconds.
        value = float(value) / (1000 if float(value) > 10_000_000_000 else 1)
        return _dt.datetime.fromtimestamp(value, _dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if isinstance(value, str) and value:
        return value
    return _now()


def _sort_timestamp(value: Any) -> float:
    if isinstance(value, (int, float)):
        number = float(value)
        return number / 1000 if number > 10_000_000_000 else number
    if isinstance(value, str):
        try:
            return _dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0.0
    return 0.0


def _stable_id(provider: str, source: str, suffix: str) -> str:
    digest = hashlib.sha256(f"{provider}|{source}|{suffix}".encode("utf-8", "replace")).hexdigest()
    return f"{provider}-{digest[:32]}"


def _row_key(row: Mapping[str, Any], index: int) -> str:
    """Stable identity across byte-sized polling batches and replays."""
    value = _first(row, "uuid", "eventId", "event_id", "id", "bubbleId", "bubble_id", "promptId", "prompt_id")
    if value not in (None, ""):
        return str(value)
    try:
        material = json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        material = str(row)
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:32] or str(index)


def _first(row: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def _session(row: Mapping[str, Any], fallback: str) -> str:
    value = _first(row, "sessionId", "session_id", "session", "conversationId", "conversation_id", "composerId")
    return str(value) if value not in (None, "") else fallback


def _event(
    provider: str,
    source: str,
    event_type: str,
    *,
    session: str,
    turn: Optional[str] = None,
    tool_call: Optional[str] = None,
    tool_name: Optional[str] = None,
    timestamp: Any = None,
    text: Optional[str] = None,
    command: Optional[str] = None,
    model: Optional[str] = None,
    action: Optional[str] = None,
    path: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    identity: str = "event",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schemaVersion": 2,
        "adapterVersion": ADAPTER_VERSION,
        "source": f"agentreins-native:{provider}",
        "eventId": _stable_id(provider, source, identity),
        "eventType": event_type,
        "provider": provider,
        "sessionId": session,
        "turnId": turn,
        "toolCallId": tool_call,
        "toolName": tool_name,
        "timestamp": _timestamp(timestamp),
        "text": text[:MAX_TEXT] if isinstance(text, str) else text,
        "command": command[:MAX_TEXT] if isinstance(command, str) else command,
        "model": model,
        "action": action,
        "path": path,
        "metadata": dict(metadata or {}),
        # A native transcript has no HTTPS origin.  This value is useful in a
        # UI while remaining harmless to the browser Native Host validator.
        "url": f"native://{provider}/{session}",
    }
    return {key: value for key, value in payload.items() if value not in (None, "", {})}


def _contents(message: Any) -> list[Mapping[str, Any]]:
    if isinstance(message, str):
        return [{"type": "text", "text": message}]
    if isinstance(message, list):
        return [item for item in message if isinstance(item, Mapping)]
    if isinstance(message, Mapping):
        value = message.get("content")
        if isinstance(value, list):
            return [item for item in value if isinstance(item, Mapping)]
        if isinstance(value, str):
            return [{"type": "text", "text": value}]
    return []


def _content_text(message: Any) -> Optional[str]:
    values: list[str] = []
    for item in _contents(message):
        item_type = str(item.get("type") or "")
        if item_type in {"text", "input_text", "output_text", "message"}:
            value = _text(item.get("text") if "text" in item else item.get("content"))
            if value:
                values.append(value)
    if not values and isinstance(message, str):
        return message[:MAX_TEXT]
    return "\n".join(values)[:MAX_TEXT] or None


def _provider_from_path(path: Path) -> Optional[str]:
    lower = str(path).lower().replace("\\", "/")
    markers = (
        ("/.codex/", "codex"), ("/.claude/", "claude"),
        ("/.qoder/", "qoder"), ("/.workbuddy/", "workbuddy"),
        ("/.kiro/", "kiro"), ("/agent-transcripts/", "cursor"),
        ("/.cursor/", "cursor"), ("/.codeium/", "windsurf"),
    )
    for marker, provider in markers:
        if marker in lower:
            return provider
    return None


def _codex(rows: Iterable[Mapping[str, Any]], source: str, fallback: str, state: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    state = state if state is not None else {}
    result: list[dict[str, Any]] = []
    turn: Optional[str] = state.get("turn")
    session = str(state.get("session") or fallback)
    model: Optional[str] = state.get("model")
    tool_names: dict[str, str] = state.setdefault("tool_names", {})
    workspace: Optional[str] = state.get("workspace")
    for index, row in enumerate(rows):
        row_key = _row_key(row, index)
        payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else row
        typ = str(row.get("type") or payload.get("type") or "")
        ts = _first(row, "timestamp", "ts") or _first(payload, "timestamp", "ts")
        session = str(_first(payload, "session_id", "sessionId") or (payload.get("id") if typ in {"session_meta", "turn_context"} else None) or session)
        workspace = str(_first(payload, "cwd", "workspace", "workdir") or workspace or "") or None
        if typ == "turn_context":
            turn = str(_first(payload, "turn_id", "turnId") or turn or "") or None
            model = str(_first(payload, "model", "model_name") or model or "") or None
            result.append(_event("codex", source, "context", session=session, turn=turn, timestamp=ts,
                                 model=model, command=_json({k: payload.get(k) for k in ("cwd", "model", "effort", "sandbox_policy") if k in payload}),
                                 metadata={"workspace": workspace} if workspace else None,
                                 tool_name="codex.turn_context", action="captured", identity=f"{row_key}:turn"))
            continue
        if typ == "event_msg" and isinstance(payload.get("item"), Mapping):
            item = payload["item"]
            if str(item.get("type")) == "UserMessage":
                text = _content_text(item.get("content")) or _text(item.get("text"))
                if text:
                    turn = str(_first(payload, "turn_id", "turnId") or item.get("id") or turn or "") or None
                    result.append(_event("codex", source, "prompt", session=session, turn=turn, timestamp=ts,
                                         text=text, model=model, action="sent", metadata={"workspace": workspace} if workspace else None, identity=f"{row_key}:prompt"))
            continue
        if typ == "response_item":
            role = str(payload.get("role") or "")
            payload_type = str(payload.get("type") or "")
            turn_value = _first(payload, "turn_id", "turnId") or turn
            turn = str(turn_value) if turn_value else None
            text = _content_text(payload.get("content"))
            if payload_type == "message" and role in {"user", "developer", "assistant"} and text:
                event_type = "prompt" if role == "user" else "response" if role == "assistant" else "context"
                result.append(_event("codex", source, event_type, session=session, turn=turn, timestamp=ts,
                                     text=text, model=model, action="sent" if event_type == "prompt" else "received",
                                     tool_name="codex.developer_instructions" if role == "developer" else None,
                                     metadata={"workspace": workspace} if workspace else None, identity=f"{row_key}:{role}"))
                continue
            if payload_type in {"custom_tool_call", "function_call", "tool_call"}:
                call_id = str(_first(payload, "call_id", "callId", "id") or f"{index}")
                name = str(_first(payload, "name", "tool_name", "toolName") or "unknown_tool")
                namespace = payload.get("namespace")
                if namespace:
                    name = f"{namespace}__{name}"
                tool_names[call_id] = name
                result.append(_event("codex", source, "tool_call", session=session, turn=turn, tool_call=call_id,
                                     tool_name=name, timestamp=ts, command=_text(_first(payload, "input", "arguments")),
                                     model=model, action="requested", metadata={"workspace": workspace} if workspace else None, identity=f"{row_key}:call:{call_id}"))
                continue
            if payload_type in {"custom_tool_call_output", "function_call_output", "tool_result"}:
                call_id = str(_first(payload, "call_id", "callId", "tool_call_id", "toolCallId") or f"{index}")
                result.append(_event("codex", source, "tool_result", session=session, turn=turn, tool_call=call_id,
                                     tool_name=tool_names.get(call_id), timestamp=ts,
                                     text=_text(_first(payload, "output", "result", "content")), model=model,
                                     action="completed", metadata={"workspace": workspace} if workspace else None, identity=f"{row_key}:result:{call_id}"))
                continue
        if typ == "token_usage_record":
            usage = payload.get("usage") if isinstance(payload.get("usage"), Mapping) else payload
            result.append(_event("codex", source, "context", session=session, turn=turn, timestamp=ts,
                                 model=model, tool_name="codex.usage", command=_json(usage), action="reported",
                                 metadata={"workspace": workspace} if workspace else None, identity=f"{row_key}:usage"))
    state.update({"turn": turn, "session": session, "model": model, "workspace": workspace})
    return result


def _workbuddy(rows: Iterable[Mapping[str, Any]], source: str, fallback: str, state: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    """Parse WorkBuddy's local project JSONL message/function-call rows."""
    state = state if state is not None else {}
    result: list[dict[str, Any]] = []
    current_turn: dict[str, str] = state.setdefault("current_turn", {})
    names: dict[str, str] = state.setdefault("tool_names", {})
    for index, row in enumerate(rows):
        row_key = _row_key(row, index)
        session = _session(row, fallback)
        timestamp = _first(row, "timestamp", "ts")
        typ = str(row.get("type") or "")
        provider_data = row.get("providerData") if isinstance(row.get("providerData"), Mapping) else {}
        model = _first(provider_data, "requestModelName", "model")
        if typ == "message" and row.get("role") == "user":
            text = _content_text(row.get("content")) or _text(row.get("content"))
            if text:
                turn = str(_first(row, "id", "turnId", "turn_id") or row_key)
                current_turn[session] = turn
                result.append(_event("workbuddy", source, "prompt", session=session, turn=turn,
                                     timestamp=timestamp, text=text, model=model, action="sent",
                                     metadata={"traceId": provider_data.get("traceId")} if provider_data.get("traceId") else None,
                                     identity=f"{row_key}:message:user:{timestamp}"))
            continue
        if typ == "message" and row.get("role") == "assistant":
            text = _content_text(row.get("content")) or _text(row.get("content"))
            if text:
                result.append(_event("workbuddy", source, "response", session=session,
                                     turn=current_turn.get(session), timestamp=timestamp, text=text,
                                     model=model, action=str(row.get("status") or "received"),
                                     identity=f"{row_key}:message:assistant:{timestamp}"))
            continue
        if typ == "reasoning":
            text = _text(row.get("content") or row.get("rawContent"))
            if text:
                result.append(_event("workbuddy", source, "reasoning", session=session,
                                     turn=current_turn.get(session), timestamp=timestamp, text=text,
                                     model=model, action="observed", identity=f"{row_key}:reasoning:{timestamp}"))
            continue
        if typ not in {"function_call", "function_call_result"}:
            continue
        call_id = str(_first(row, "callId", "call_id") or row_key)
        name = str(_first(row, "name", "toolName") or names.get(call_id) or "unknown_tool")
        if typ == "function_call":
            names[call_id] = name
            result.append(_event("workbuddy", source, "tool_call", session=session,
                                 turn=current_turn.get(session), tool_call=call_id, tool_name=name,
                                 timestamp=timestamp, command=_text(_first(row, "arguments", "input")),
                                 model=model, action=str(row.get("status") or "requested"),
                                 identity=f"{row_key}:call:{call_id}:{timestamp}"))
        else:
            result.append(_event("workbuddy", source, "tool_result", session=session,
                                 turn=current_turn.get(session), tool_call=call_id, tool_name=name,
                                 timestamp=timestamp, text=_text(_first(row, "output", "result")),
                                 model=model, action=str(row.get("status") or "completed"),
                                 identity=f"{row_key}:result:{call_id}:{timestamp}"))
    state.update({"current_turn": current_turn, "tool_names": names})
    return result


def _claude_like(provider: str, rows: Iterable[Mapping[str, Any]], source: str, fallback: str, state: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    state = state if state is not None else {}
    result: list[dict[str, Any]] = []
    turn_by_uuid: dict[str, str] = state.setdefault("turn_by_uuid", {})
    current_turn: Optional[str] = state.get("current_turn")
    tool_names: dict[str, str] = state.setdefault("tool_names", {})
    for index, row in enumerate(rows):
        row_key = _row_key(row, index)
        session = _session(row, fallback)
        ts = _first(row, "timestamp", "ts", "createdAt", "created_at")
        typ = str(row.get("type") or row.get("eventType") or "")
        message = row.get("message") if isinstance(row.get("message"), Mapping) else row
        workspace = _first(row, "cwd", "workspace", "workdir") or _first(message, "cwd", "workspace", "workdir")
        contents = _contents(message.get("content") if isinstance(message, Mapping) else message)
        parent = row.get("parentUuid") or row.get("parent_uuid")
        turn = turn_by_uuid.get(str(parent)) if parent else None
        turn = str(_first(row, "turnId", "turn_id", "promptId", "requestSetId") or turn or current_turn or "") or None
        uuid = str(_first(row, "uuid", "id", "eventId") or row_key)
        if typ in {"user", "prompt"} and not any(str(x.get("type")) in {"tool_result", "tool_use"} for x in contents):
            text = _content_text(message.get("content") if isinstance(message, Mapping) else message) or _text(row.get("prompt"))
            if not text and isinstance(row.get("humanInput"), Mapping):
                text = _text(row["humanInput"].get("text"))
            if text:
                # A new user prompt starts a new turn even if its parent is a
                # previous assistant response. Native explicit IDs win.
                current_turn = str(_first(row, "turnId", "turn_id", "promptId", "requestSetId") or uuid)
                turn = current_turn
                turn_by_uuid[uuid] = turn
                result.append(_event(provider, source, "prompt", session=session, turn=turn, timestamp=ts, text=text,
                                     model=_first(message, "model") if isinstance(message, Mapping) else None,
                                     action="sent", metadata={"workspace": workspace} if workspace else None, identity=f"{uuid}:prompt"))
        if typ in {"assistant", "response"}:
            text_parts: list[str] = []
            for item in contents:
                if str(item.get("type")) in {"text", "output_text"} and _text(item.get("text")):
                    text_parts.append(_text(item.get("text")) or "")
                elif str(item.get("type")) in {"thinking", "reasoning"} and _text(item.get("thinking") or item.get("text")):
                    result.append(_event(provider, source, "reasoning", session=session, turn=turn, timestamp=ts,
                                         text=_text(item.get("thinking") or item.get("text")), action="observed",
                                         metadata={"workspace": workspace} if workspace else None, identity=f"{row_key}:reasoning:{len(result)}"))
            if not text_parts and _text(row.get("response")):
                text_parts.append(_text(row.get("response")) or "")
            if text_parts:
                result.append(_event(provider, source, "response", session=session, turn=turn, timestamp=ts,
                                     text="\n".join(text_parts), model=_first(message, "model") if isinstance(message, Mapping) else None,
                                     action=str(_first(message, "stop_reason", "status") or "received"), metadata={"workspace": workspace} if workspace else None, identity=f"{row_key}:response"))
        for item in contents:
            item_type = str(item.get("type") or "")
            if item_type in {"tool_use", "function_call", "tool_call"}:
                call_id = str(_first(item, "id", "call_id", "toolCallId") or f"{uuid}:tool")
                name = str(_first(item, "name", "tool_name", "toolName") or "unknown_tool")
                tool_names[call_id] = name
                result.append(_event(provider, source, "tool_call", session=session, turn=turn, tool_call=call_id,
                                     tool_name=name, timestamp=ts, command=_json(_first(item, "input", "arguments", "parameters")),
                                     action="requested", metadata={"workspace": workspace} if workspace else None, identity=f"{row_key}:call:{call_id}"))
            elif item_type in {"tool_result", "function_result", "tool_output"}:
                call_id = str(_first(item, "tool_use_id", "tool_call_id", "call_id", "toolCallId") or f"{uuid}:tool")
                result.append(_event(provider, source, "tool_result", session=session, turn=turn, tool_call=call_id,
                                     tool_name=tool_names.get(call_id), timestamp=ts,
                                     text=_text(_first(item, "content", "output", "result")),
                                     action="failed" if item.get("is_error") else "completed", metadata={"workspace": workspace} if workspace else None, identity=f"{row_key}:result:{call_id}"))
        if typ in {"runtime-config", "permission-mode", "workspace-directories", "context"}:
            result.append(_event(provider, source, "context", session=session, turn=turn, timestamp=ts,
                                 command=_json(row), action="observed", identity=f"{row_key}:context"))
        if turn:
            turn_by_uuid[uuid] = turn
    state.update({"turn_by_uuid": turn_by_uuid, "current_turn": current_turn, "tool_names": tool_names})
    return result


def _cursor(rows: Iterable[Mapping[str, Any]], source: str, fallback: str, state: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    """Project Cursor transcript JSON/JSONL and common exported bubble shapes."""
    flattened: list[Mapping[str, Any]] = []
    for row in rows:
        nested = row.get("bubbles") if isinstance(row.get("bubbles"), list) else row.get("messages")
        if isinstance(nested, list):
            header = {k: row[k] for k in ("sessionId", "composerId", "model", "workspace") if k in row}
            flattened.extend([dict(header, **item) for item in nested if isinstance(item, Mapping)])
        else:
            flattened.append(row)
    flattened.sort(key=lambda row: _sort_timestamp(_first(row, "createdAt", "timestamp", "updatedAt")))
    state = state if state is not None else {}
    result: list[dict[str, Any]] = []
    turn: Optional[str] = state.get("turn")
    for index, row in enumerate(flattened):
        row_key = _row_key(row, index)
        session = _session(row, fallback)
        ident = str(_first(row, "bubbleId", "id", "eventId") or row_key)
        ts = _first(row, "createdAt", "timestamp", "updatedAt")
        bubble_type = row.get("type")
        role = str(row.get("role") or "")
        text = _text(row.get("text") or row.get("content"))
        if bubble_type in (1, "1") or role == "user" or role == "human":
            if text:
                turn = ident
                result.append(_event("cursor", source, "prompt", session=session, turn=turn, timestamp=ts,
                                     text=text, model=_first(row, "model", "modelName"), action="sent", metadata={"workspace": row.get("workspace")} if row.get("workspace") else None, identity=f"{ident}:prompt"))
            continue
        tool = row.get("toolFormerData") if isinstance(row.get("toolFormerData"), Mapping) else row.get("tool")
        if isinstance(tool, Mapping):
            call_id = str(_first(tool, "toolCallId", "call_id", "id") or f"{ident}:tool")
            name = str(_first(tool, "name", "toolName") or "unknown_tool")
            result.append(_event("cursor", source, "tool_call", session=session, turn=turn, tool_call=call_id,
                                 tool_name=name, timestamp=ts, command=_text(_first(tool, "params", "arguments", "input")),
                                 action="requested", metadata={"workspace": row.get("workspace")} if row.get("workspace") else None, identity=f"{ident}:call"))
            if _first(tool, "result", "output") is not None:
                result.append(_event("cursor", source, "tool_result", session=session, turn=turn, tool_call=call_id,
                                     tool_name=name, timestamp=ts, text=_text(_first(tool, "result", "output")),
                                     action=str(tool.get("status") or "completed"), metadata={"workspace": row.get("workspace")} if row.get("workspace") else None, identity=f"{ident}:result"))
            continue
        if role in {"assistant", "model"} or bubble_type in (2, "2"):
            if text:
                result.append(_event("cursor", source, "response", session=session, turn=turn, timestamp=ts,
                                     text=text, model=_first(row, "model", "modelName"), action="received", metadata={"workspace": row.get("workspace")} if row.get("workspace") else None, identity=f"{row_key}:response"))
    state["turn"] = turn
    return result


def parse_records(provider: str, records: Iterable[Mapping[str, Any]], source: str, session_hint: str, state: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    """Parse records; pass mutable ``state`` to preserve append-stream context.

    State is scoped to one source by NativeSessionReader. Sessions within
    generic/Claude/WorkBuddy exports get separate contexts, preventing one
    conversation's current turn or tool names leaking into another.
    """
    provider = provider.lower()
    state = state if state is not None else {}
    events = []
    for row in records:
        if not isinstance(row, Mapping):
            continue
        session = _session(row, session_hint)
        context = state if provider == "codex" else state.setdefault("sessions", {}).setdefault(session, {})
        payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else row
        workspace = _first(row, "cwd", "workspace", "workdir") or _first(payload, "cwd", "workspace", "workdir") or context.get("workspace")
        if isinstance(workspace, str):
            context["workspace"] = workspace
        if provider == "codex":
            parsed = _codex([row], source, session_hint, context)
        elif provider == "cursor":
            parsed = _cursor([row], source, session, context)
        elif provider == "workbuddy":
            parsed = _workbuddy([row], source, session, context)
        else:
            parsed = _claude_like(provider, [row], source, session, context)
        workspace = context.get("workspace")
        for event in parsed:
            if workspace:
                event.setdefault("metadata", {}).setdefault("workspace", workspace)
            events.append(event)
        # Tool history is a bounded join cache, not an unbounded transcript.
        for name in ("tool_names", "turn_by_uuid"):
            cache = context.get(name)
            if isinstance(cache, dict):
                while len(cache) > 2048:
                    cache.pop(next(iter(cache)))
    return events


class NativeSessionReader:
    """Incrementally discover and parse provider session transcripts."""

    def __init__(self, roots: Optional[Mapping[str, Iterable[Path]]] = None,
                 cursor_databases: Optional[Iterable[Path]] = None):
        configured_roots = default_native_roots() if roots is None else roots
        self.roots = {provider: [Path(path).expanduser() for path in paths]
                      for provider, paths in configured_roots.items()}
        self.cursor_databases = [Path(path).expanduser() for path in
                                 (cursor_databases if cursor_databases is not None else default_cursor_databases())]
        self.offsets: dict[str, int] = {}
        self.fingerprints: dict[str, tuple[int, int, int]] = {}
        self._cursor_fingerprints: dict[str, tuple[int, int]] = {}
        # Parser state persists across append-only polls.  Without it a tool
        # result in a later batch loses the call's name and active turn.
        self._parser_state: dict[tuple[str, str], dict[str, Any]] = {}
        self._discovery_cache: list[tuple[str, Path]] = []
        self._discover_after = 0.0
        self.last_errors = 0
        self.last_files = 0

    def files(self) -> list[tuple[str, Path]]:
        if time.monotonic() < self._discover_after:
            return self._discovery_cache
        found: list[tuple[str, Path]] = []
        for provider, roots in self.roots.items():
            for root in roots:
                if not root.exists():
                    continue
                try:
                    root_matches = 0
                    if root.is_file():
                        if root.suffix.lower() in {".jsonl", ".ndjson", ".json"}:
                            found.append((provider, root))
                        continue
                    # Bound directory work: home folders may contain large
                    # workspaces or generated trees below an agent directory.
                    visited = 0
                    for directory, subdirs, filenames in os.walk(root):
                        subdirs[:] = [name for name in subdirs if name not in {"node_modules", ".git", "Cache", "CachedData", "logs"}]
                        visited += 1
                        if visited > 1000:
                            break
                        for name in filenames:
                            path = Path(directory) / name
                            suffix = path.suffix.lower()
                            if suffix in {".jsonl", ".ndjson"} or (suffix == ".json" and provider == "cursor"):
                                found.append((provider, path))
                                root_matches += 1
                                if root_matches >= MAX_FILES_PER_POLL * 8:
                                    break
                        if root_matches >= MAX_FILES_PER_POLL * 8:
                            break
                except OSError:
                    continue
        # Most recent records first, with a hard cap to prevent a large home
        # directory from turning a UI refresh into an unbounded scan.
        def modification_time(item: tuple[str, Path]) -> float:
            try:
                return item[1].stat().st_mtime
            except OSError:
                return 0
        found.sort(key=modification_time, reverse=True)
        self._discovery_cache = found[:MAX_FILES_PER_POLL]
        self._discover_after = time.monotonic() + 5.0
        return self._discovery_cache

    @staticmethod
    def _records(data: bytes, suffix: str) -> list[Mapping[str, Any]]:
        if suffix == ".json":
            try:
                value = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return []
            if isinstance(value, list):
                return [row for row in value if isinstance(row, Mapping)]
            return [value] if isinstance(value, Mapping) else []
        result: list[Mapping[str, Any]] = []
        for line in data.splitlines():
            if not line.strip():
                continue
            try:
                value = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                # A trailing partial row is deliberately ignored and will be
                # re-read because the checkpoint advances only to full lines.
                continue
            if isinstance(value, Mapping):
                result.append(value)
        return result

    def poll(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        errors = 0
        files_seen = 0
        for provider, path in self.files():
            try:
                stat = path.stat()
                fingerprint = (int(getattr(stat, "st_ino", 0)), int(stat.st_size), int(stat.st_mtime_ns))
                key = str(path)
                old_fingerprint = self.fingerprints.get(key)
                previous = self.offsets.get(key, 0)
                rewritten = old_fingerprint and fingerprint[2] != old_fingerprint[2] and fingerprint[1] <= previous
                replaced = old_fingerprint and old_fingerprint[0] != fingerprint[0]
                if replaced or fingerprint[1] < previous or rewritten:
                    previous = max(0, fingerprint[1] - MAX_BYTES_PER_FILE) if path.suffix.lower() != ".json" else 0
                    self._parser_state.pop((provider, key), None)
                self.fingerprints[key] = fingerprint
                if key not in self.offsets and path.suffix.lower() != ".json" and fingerprint[1] > MAX_BYTES_PER_FILE:
                    # Start with a bounded tail of historical transcripts;
                    # subsequent polls continue from a complete line boundary.
                    previous = fingerprint[1] - MAX_BYTES_PER_FILE
                if fingerprint[1] <= previous:
                    continue
                read_size = min(MAX_BYTES_PER_FILE, fingerprint[1] - previous)
                with path.open("rb") as handle:
                    handle.seek(previous)
                    data = handle.read(read_size)
                if not data:
                    continue
                # JSON files are snapshots, not append-only streams.
                if path.suffix.lower() == ".json":
                    previous = 0
                    with path.open("rb") as handle:
                        data = handle.read(MAX_BYTES_PER_FILE)
                if path.suffix.lower() != ".json":
                    # Do not advance past a partial final JSONL row: it will be
                    # completed by the writer and re-read on the next poll.
                    complete_length = data.rfind(b"\n") + 1
                    if complete_length <= 0:
                        continue
                    data = data[:complete_length]
                records = self._records(data, path.suffix.lower())
                parsed = parse_records(provider, records, key, path.stem,
                                       self._parser_state.setdefault((provider, key), {}))
                events.extend(parsed)
                self.offsets[key] = (previous + len(data)) if path.suffix.lower() != ".json" else fingerprint[1]
                files_seen += 1
            except (OSError, UnicodeError, ValueError):
                errors += 1
        for database in self.cursor_databases:
            try:
                stat = database.stat()
                fingerprint = (int(stat.st_size), int(stat.st_mtime_ns))
                key = str(database)
                if self._cursor_fingerprints.get(key) == fingerprint:
                    continue
                self._cursor_fingerprints[key] = fingerprint
                events.extend(self._read_cursor_database(database))
                files_seen += 1
            except FileNotFoundError:
                continue
            except (OSError, sqlite3.Error):
                errors += 1
        self.last_errors = errors
        self.last_files = files_seen
        return events

    @staticmethod
    def _read_cursor_database(path: Path) -> list[dict[str, Any]]:
        """Read one recent non-draft Composer from Cursor's local SQLite DB.

        This is deliberately read-only and schema-tolerant. Missing tables,
        newer Cursor schemas, and locked databases simply produce no evidence.
        No workspace file content or editor credentials are queried.
        """
        uri = path.resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=0.25)
        connection.row_factory = sqlite3.Row
        try:
            try:
                try:
                    headers = connection.execute(
                        "SELECT composerId,lastUpdatedAt,value FROM composerHeaders "
                        "WHERE COALESCE(isArchived,0)=0 ORDER BY lastUpdatedAt DESC LIMIT 8"
                    ).fetchall()
                except sqlite3.Error:
                    headers = connection.execute(
                        "SELECT composerId,lastUpdatedAt,value FROM composerHeaders ORDER BY lastUpdatedAt DESC LIMIT 8"
                    ).fetchall()
            except sqlite3.Error:
                return []
            for header_row in headers:
                composer_id = str(header_row["composerId"] or "")
                try:
                    header = json.loads(str(header_row["value"] or "{}"))
                except (TypeError, json.JSONDecodeError):
                    continue
                if not composer_id or not isinstance(header, Mapping) or header.get("isDraft") is True:
                    continue
                try:
                    bubble_rows = connection.execute(
                        "SELECT key,value FROM cursorDiskKV WHERE key LIKE ? ORDER BY key",
                        (f"bubbleId:{composer_id}:%",),
                    ).fetchall()
                except sqlite3.Error:
                    continue
                bubbles: list[dict[str, Any]] = []
                for bubble_row in bubble_rows:
                    try:
                        bubble = json.loads(str(bubble_row["value"] or "{}"))
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if not isinstance(bubble, dict):
                        continue
                    key = str(bubble_row["key"] or "")
                    bubble.setdefault("bubbleId", key.rsplit(":", 1)[-1])
                    bubbles.append(bubble)
                if not bubbles:
                    continue
                envelope = {
                    "composerId": composer_id,
                    "model": ((header.get("modelConfig") or {}).get("modelName")
                              if isinstance(header.get("modelConfig"), Mapping) else None),
                    "workspace": ((header.get("workspaceIdentifier") or {}).get("uri")
                                  if isinstance(header.get("workspaceIdentifier"), Mapping) else None),
                    "bubbles": bubbles,
                }
                return parse_records("cursor", [envelope], str(path), composer_id)
            return []
        finally:
            connection.close()


def default_native_roots(home: Optional[Path] = None) -> dict[str, list[Path]]:
    """Return provider roots for Windows, Linux, and macOS user profiles."""
    home = home or Path.home()
    system = platform.system().lower()
    roots: dict[str, list[Path]] = {
        "codex": [home / ".codex" / "sessions", home / ".codex" / "archived_sessions"],
        "claude": [home / ".claude" / "projects"],
        "qoder": [home / ".qoder" / "projects"],
        "workbuddy": [home / ".workbuddy" / "projects"],
        "cursor": [home / ".cursor" / "agent-transcripts"],
    }
    if system == "windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        roots["cursor"].append(appdata / "Cursor" / "User" / "agent-transcripts")
    elif system == "darwin":
        support = home / "Library" / "Application Support"
        roots["cursor"].append(support / "Cursor" / "User" / "agent-transcripts")
    else:
        config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        roots["cursor"].append(config / "Cursor" / "User" / "agent-transcripts")
    return roots


def default_cursor_databases(home: Optional[Path] = None) -> list[Path]:
    """Cursor stores its Composer transcripts in state.vscdb per user profile."""
    home = home or Path.home()
    system = platform.system().lower()
    if system == "windows":
        base = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
    elif system == "darwin":
        base = home / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
    return [base / "Cursor" / "User" / "globalStorage" / "state.vscdb"]


__all__ = ["ADAPTER_VERSION", "NativeSessionReader", "default_cursor_databases", "default_native_roots", "parse_records"]
