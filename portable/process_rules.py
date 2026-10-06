"""Portable process rules, IP ownership cache and explicit proxy-log reader.

Process rules are detection/alert rules by default.  They do not intercept or
block launches.  Termination is a separately requested action and requires an
identity check to avoid killing a recycled PID.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import os
import re
import signal
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional


OPS = {"delete", "modify", "read", "move", "rename", "execute"}
SEVERITY = {"info", "medium", "high", "critical"}


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")[:64] or "rule"


def parse_rule_text(text: str, project_root: Optional[str] = None) -> dict[str, Any]:
    """Deterministically parse simple Chinese/English local protection text."""
    original = str(text or "").strip()
    lower = original.lower()
    operations = []
    tests = (("delete", ("删除", "delete", "rm")), ("modify", ("修改", "改动", "写", "modify", "write", "change")),
             ("read", ("读取", "读", "read", "cat")), ("move", ("移动", "move", "mv")),
             ("rename", ("重命名", "rename")), ("execute", ("执行", "execute", "exec")))
    for operation, words in tests:
        if any(word in (original if any(ord(c) > 127 for c in word) else lower) for word in words):
            operations.append(operation)
    operations = list(dict.fromkeys(operations)) or ["delete", "modify"]
    target = None
    for match in re.finditer(r"(?:~|[A-Za-z]:)?[/\\\w.\-]+", original):
        value = match.group(0).rstrip(".,;:)")
        if "/" in value or "\\" in value or value.startswith("."):
            target = value
            break
    target = target or project_root or os.environ.get("AGENTGUARD_PROJECT_ROOT") or str(Path.home() / "Projects")
    if target.startswith("~"):
        target = str(Path(target).expanduser())
    elif project_root and not os.path.isabs(target) and not re.match(r"^[A-Za-z]:[\\/]", target):
        target = str(Path(project_root) / target)
    severity = "critical" if "delete" in operations else "high" if any(op in operations for op in ("modify", "execute")) else "medium"
    return {"id": "local_" + _slug(target), "kind": "file", "watch": [target], "ops": operations,
            "severity": severity, "action": "alert", "restore": False,
            "message": "Agent " + ", ".join(operations) + " " + target, "naturalLanguage": original}


class ProcessRuleStore:
    """Atomic JSON CRUD store. Invalid rules are rejected instead of ignored."""
    def __init__(self, root: Path):
        self.path = Path(root) / "process-rules.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def list(self) -> list[dict[str, Any]]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            return [dict(item) for item in value.get("rules", value) if isinstance(item, Mapping)]
        except (OSError, ValueError, TypeError):
            return []

    def _save(self, rules: list[dict[str, Any]]) -> None:
        payload = json.dumps({"version": 1, "rules": rules}, ensure_ascii=True, sort_keys=True, indent=2)
        fd, name = tempfile.mkstemp(prefix=".process-rules-", dir=str(self.path.parent), text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
        finally:
            try: os.unlink(name)
            except OSError: pass

    @staticmethod
    def _validate(rule: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(rule)
        result["id"] = str(result.get("id") or "rule")
        result["pattern"] = str(result.get("pattern") or "")
        if result.get("pattern"):
            re.compile(result["pattern"], re.I)
        result["severity"] = str(result.get("severity") or "high").lower()
        if result["severity"] not in SEVERITY: raise ValueError("invalid severity")
        result["action"] = str(result.get("action") or "alert").lower()
        if result["action"] not in {"alert", "observe"}: raise ValueError("process rules do not block launches")
        return result

    def add(self, rule: Mapping[str, Any]) -> dict[str, Any]:
        value = self._validate(rule); rules = [item for item in self.list() if item.get("id") != value["id"]]; rules.append(value); self._save(rules); return value
    def update(self, rule_id: str, **changes: Any) -> dict[str, Any]:
        rules = self.list(); existing = next((item for item in rules if item.get("id") == rule_id), None)
        if existing is None: raise KeyError(rule_id)
        existing.update(changes); return self.add(existing)
    def remove(self, rule_id: str) -> bool:
        rules = self.list(); kept = [item for item in rules if item.get("id") != rule_id]
        changed = len(kept) != len(rules)
        if changed: self._save(kept)
        return changed


class ProcessMonitor:
    def __init__(self, rules: Iterable[Mapping[str, Any]]):
        self.rules = [ProcessRuleStore._validate(rule) for rule in rules]

    def evaluate(self, processes: Iterable[Mapping[str, Any]], observed_at: Optional[str] = None) -> list[dict[str, Any]]:
        timestamp = observed_at or _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")
        alerts = []
        for process in processes:
            pid = str(process.get("pid") or "")
            command = str(process.get("command") or process.get("executable") or "")
            for rule in self.rules:
                pattern = rule.get("pattern") or ""
                watch = [str(path).lower() for path in (rule.get("watch") or [])]
                if pattern and not re.search(pattern, command, re.I): continue
                if watch and not any(path in command.lower() for path in watch): continue
                alerts.append({"id": f"{rule['id']}:{pid}:{timestamp}", "ruleId": rule["id"], "pid": pid,
                               "ppid": str(process.get("ppid") or ""), "command": command, "agent": process.get("agent"),
                               "severity": rule.get("severity", "high"), "action": "alert", "status": "observed",
                               "timestamp": timestamp, "message": rule.get("message", "Process rule matched"),
                               "confidence": "confirmed" if pid else "unknown", "identity": {"pid": pid, "startTime": process.get("startTime", process.get("createTime")), "executable": process.get("executable")}})
        return alerts


class ProcessController:
    """Explicit termination with PID-reuse protection; never automatic."""
    def __init__(self, lookup: Optional[Callable[[str], Optional[Mapping[str, Any]]]] = None, terminator: Optional[Callable[[int], None]] = None):
        self.lookup = lookup
        self.terminator = terminator or (lambda pid: os.kill(pid, signal.SIGTERM))

    def terminate(self, alert: Mapping[str, Any], *, expected_start_time: Any = None, explicit: bool = False) -> dict[str, Any]:
        if not explicit: return {"success": False, "status": "confirmation_required", "pid": alert.get("pid")}
        pid_text = str(alert.get("pid") or "")
        if not pid_text.isdigit(): return {"success": False, "status": "invalid_pid"}
        expected = expected_start_time if expected_start_time is not None else (alert.get("identity") or {}).get("startTime")
        current = self.lookup(pid_text) if self.lookup else None
        if expected is not None and (not current or str(current.get("startTime", current.get("createTime"))) != str(expected)):
            return {"success": False, "status": "identity_mismatch", "pid": pid_text}
        try:
            self.terminator(int(pid_text))
            return {"success": True, "status": "terminate_requested", "pid": pid_text, "automatic": False}
        except (OSError, ValueError) as error:
            return {"success": False, "status": "terminate_failed", "pid": pid_text, "error": str(error)}


class IPGeolocationCache:
    def __init__(self, path: Path, ttl_days: int = 30):
        self.path, self.ttl = Path(path), ttl_days * 86400
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try: self.records = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError): self.records = {}

    @staticmethod
    def is_public(ip: str) -> bool:
        try: return ipaddress.ip_address(ip).is_global
        except ValueError: return False

    def lookup(self, ip: str, resolver: Optional[Callable[[str], Mapping[str, Any]]] = None) -> Optional[dict[str, Any]]:
        if not self.is_public(ip): return None
        now = _dt.datetime.now(_dt.timezone.utc).timestamp(); cached = self.records.get(ip)
        if cached and now - float(cached.get("fetchedAt", 0)) < self.ttl: return dict(cached)
        if resolver is None: return None
        value = dict(resolver(ip)); value.update(ip=ip, fetchedAt=now); self.records[ip] = value
        self.path.write_text(json.dumps(self.records, ensure_ascii=True, sort_keys=True), encoding="utf-8")
        return value


class ProxyAccessLogReader:
    """Explicit V2rayU destination-only reader; bodies/headers are ignored."""
    _line = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? from (?:tcp:)?(?:127\.0\.0\.1|\[::1\]):(\d+) accepted //(?:tcp:)?([^:\s]+):(\d+)", re.M)
    def __init__(self, path: Path, maximum_bytes: int = 131_072): self.path, self.maximum_bytes, self.offset, self._inode = Path(path), maximum_bytes, 0, None
    def poll(self) -> list[dict[str, Any]]:
        try:
            stat = self.path.stat(); size = stat.st_size
            inode = getattr(stat, "st_ino", 0)
            if self._inode is not None and (inode != self._inode or size < self.offset):
                self.offset = 0
            self._inode = inode
            start = max(0, size - self.maximum_bytes) if self.offset == 0 else self.offset
            with self.path.open("rb") as stream:
                stream.seek(start); data = stream.read()
            self.offset = size
        except OSError: return []
        text = data.decode("utf-8", "replace"); result = []
        for match in self._line.finditer(text):
            result.append({"timestamp": match.group(1), "clientPort": int(match.group(2)), "remoteHost": match.group(3).lower(), "remotePort": int(match.group(4)), "proxyName": "V2rayU", "source": "proxy-log", "confidence": "confirmed", "evidenceType": "proxy_destination"})
        return result


__all__ = ["ProcessRuleStore", "ProcessMonitor", "ProcessController", "parse_rule_text", "IPGeolocationCache", "ProxyAccessLogReader"]
