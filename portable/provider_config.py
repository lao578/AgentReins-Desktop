"""Read-only provider endpoint discovery.

Only endpoint metadata is returned. Values that look like credentials are
never retained, even in ``raw`` fields. A configured endpoint is configuration
evidence, not proof that a request reached that host or that a server retained
any payload.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import urlsplit


_SECRET = re.compile(r"(?:api[_-]?key|access[_-]?token|secret|password|passwd|authorization|bearer|private[_-]?key)", re.I)
_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)


def _host(value: Any) -> Optional[str]:
    try:
        text = str(value or "").strip().rstrip("/,")
        if not text.lower().startswith(("http://", "https://")):
            return None
        return urlsplit(text).hostname.lower() if urlsplit(text).hostname else None
    except ValueError:
        return None


def _safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _safe(item) for key, item in value.items() if not _SECRET.search(str(key))}
    if isinstance(value, list):
        return [_safe(item) for item in value[:128]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str) and _SECRET.search(value):
            return "[REDACTED]"
        return value
    return str(value)


def _walk(value: Any, path: str = "") -> Iterable[tuple[str, str, str]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            if _SECRET.search(key_text):
                continue
            yield from _walk(item, f"{path}.{key_text}" if path else key_text)
    elif isinstance(value, list):
        for index, item in enumerate(value[:128]):
            yield from _walk(item, f"{path}[{index}]")
    elif isinstance(value, str):
        for match in _URL.finditer(value):
            host = _host(match.group(0))
            if host:
                yield host, path, match.group(0).rstrip(".,;)")


def discover(provider: str, paths: Iterable[Path]) -> list[dict[str, Any]]:
    """Inspect explicitly supplied provider config files, never mutating them."""
    provider = provider.lower()
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for candidate in paths:
        path = Path(candidate).expanduser()
        try:
            if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            continue
        for host, field, url in _walk(data):
            key = (str(path), host)
            if key in seen:
                continue
            seen.add(key)
            # Userinfo, query strings and paths can contain credentials. The
            # hostname is all the route assessment needs.
            parsed = urlsplit(url)
            safe_url = f"{parsed.scheme}://{host}"
            try:
                if parsed.port:
                    safe_url += f":{parsed.port}"
            except ValueError:
                continue
            found.append({"provider": provider, "host": host, "url": safe_url,
                          "source": "provider-config", "path": str(path),
                          "field": field, "confidence": "confirmed",
                          "identityStatus": "configured_not_observed",
                          "evidenceType": "configuration",
                          "details": _safe({"field": field})})
    return found


def default_paths(home: Optional[Path] = None) -> dict[str, list[Path]]:
    """Conservative known config locations; no broad home-directory scan."""
    home = home or Path.home()
    appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
    config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
    return {
        "codex": [home / ".codex" / "config.json"],
        "claude": [home / ".claude" / "settings.json"],
        "qoder": [home / ".qoder" / "config.json"],
        "workbuddy": [home / ".workbuddy" / "config.json", home / ".workbuddy" / "models.json"],
        "cursor": [appdata / "Cursor" / "User" / "settings.json", config / "Cursor" / "User" / "settings.json"],
    }


def discover_defaults() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for provider, paths in default_paths().items():
        result.extend(discover(provider, paths))
    return result


__all__ = ["default_paths", "discover", "discover_defaults"]
