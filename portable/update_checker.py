#!/usr/bin/env python3
"""Small, dependency-free GitHub release update client.

The portable runtime intentionally does not update itself in the background.
This module provides the safe building blocks used by the explicit desktop
update action (and is useful from scripts today): query the signed-in-free GitHub releases API,
select a platform asset, download it to a caller-owned directory, and verify a
SHA-256 sidecar before the file is made visible.  Installation/replacement is
always an explicit caller action.

Examples::

    python portable/update_checker.py --check
    python portable/update_checker.py --download ./updates --kind windows-installer

The GitHub API is the update feed.  Release jobs publish ``.sha256`` files for
all executable/package assets; when present those are used in addition to the
API's optional ``digest`` field.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import platform
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


DEFAULT_REPOSITORY = os.environ.get("AGENTREINS_UPDATE_REPOSITORY", "lao578/AgentReins-Desktop")
DEFAULT_API_URL = "https://api.github.com"
USER_AGENT = "AgentReins-update-checker/0.1"
_VERSION_RE = re.compile(r"^[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$")
_CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})\s+(?:\*?)([^\s]+)\s*$")

try:  # Use the exact build metadata when invoked from the packaged console.
    from agentreins_portable import VERSION as BUILT_VERSION
except ImportError:
    try:
        from .agentreins_portable import VERSION as BUILT_VERSION
    except ImportError:
        BUILT_VERSION = os.environ.get("AGENTREINS_VERSION", "0.1.1").lstrip("vV")


class UpdateCheckError(RuntimeError):
    """A network, API, or release metadata error."""


@functools.total_ordering
@dataclass(frozen=True)
class Version:
    """Comparable semantic-ish version used for release tags.

    AgentReins release tags are ``vMAJOR.MINOR.PATCH``.  Missing components
    are treated as zero so development builds such as ``0.1`` compare cleanly.
    Pre-release suffixes are intentionally treated as lower than a stable
    version with the same numeric components.
    """

    major: int
    minor: int = 0
    patch: int = 0
    prerelease: bool = False

    def _key(self) -> tuple[int, int, int, int]:
        # Stable releases sort after a pre-release with the same numbers.
        return self.major, self.minor, self.patch, 0 if self.prerelease else 1

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() < other._key()


def parse_version(value: str) -> Version:
    match = _VERSION_RE.match(str(value).strip())
    if not match:
        raise ValueError(f"invalid AgentReins version: {value!r}")
    major, minor, patch = (int(part or 0) for part in match.groups()[:3])
    prerelease = "-" in str(value).lstrip("vV")
    return Version(major, minor, patch, prerelease)


@dataclass(frozen=True)
class ReleaseAsset:
    name: str
    url: str
    size: int = 0
    digest: Optional[str] = None
    content_type: str = ""

    @classmethod
    def from_json(cls, value: dict[str, Any]) -> "ReleaseAsset":
        name = str(value.get("name") or "")
        url = str(value.get("browser_download_url") or value.get("url") or "")
        digest = value.get("digest")
        if digest is not None:
            digest = str(digest)
        try:
            size = int(value.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        return cls(name=name, url=url, size=size, digest=digest, content_type=str(value.get("content_type") or ""))


@dataclass(frozen=True)
class ReleaseInfo:
    version: Version
    tag_name: str
    url: str
    body: str
    published_at: Optional[str]
    assets: tuple[ReleaseAsset, ...]


@dataclass(frozen=True)
class UpdateInfo:
    current_version: str
    latest_version: str
    available: bool
    release_url: str
    tag_name: str
    assets: tuple[ReleaseAsset, ...]
    error: Optional[str] = None


def _request_json(url: str, opener: Callable[..., Any] = urlopen, timeout: float = 8.0) -> Any:
    request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT})
    try:
        with opener(request, timeout=timeout) as response:
            raw = response.read()
    except HTTPError as exc:
        raise UpdateCheckError(f"GitHub API returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise UpdateCheckError(f"GitHub API unavailable: {exc.reason}") from exc
    except OSError as exc:
        raise UpdateCheckError(f"GitHub API unavailable: {exc}") from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateCheckError("GitHub API returned invalid JSON") from exc


def fetch_latest_release(
    repository: str = DEFAULT_REPOSITORY,
    *,
    api_url: str = DEFAULT_API_URL,
    opener: Callable[..., Any] = urlopen,
    timeout: float = 8.0,
) -> ReleaseInfo:
    """Fetch the latest stable GitHub release for ``owner/repository``."""

    repository = repository.strip().strip("/")
    if not re.fullmatch(r"[^/\s]+/[^/\s]+", repository):
        raise UpdateCheckError(f"invalid GitHub repository: {repository!r}")
    endpoint = f"{api_url.rstrip('/')}/repos/{quote(repository, safe='/')}/releases/latest"
    payload = _request_json(endpoint, opener=opener, timeout=timeout)
    if not isinstance(payload, dict):
        raise UpdateCheckError("GitHub API release response was not an object")
    tag = str(payload.get("tag_name") or "")
    try:
        version = parse_version(tag)
    except ValueError as exc:
        raise UpdateCheckError(f"release has an invalid tag: {tag!r}") from exc
    raw_assets = payload.get("assets", [])
    if not isinstance(raw_assets, list):
        raw_assets = []
    assets = tuple(ReleaseAsset.from_json(item) for item in raw_assets if isinstance(item, dict))
    return ReleaseInfo(
        version=version,
        tag_name=tag,
        url=str(payload.get("html_url") or ""),
        body=str(payload.get("body") or ""),
        published_at=str(payload.get("published_at")) if payload.get("published_at") else None,
        assets=assets,
    )


def check_for_updates(
    current_version: str,
    repository: str = DEFAULT_REPOSITORY,
    *,
    api_url: str = DEFAULT_API_URL,
    opener: Callable[..., Any] = urlopen,
    timeout: float = 8.0,
) -> UpdateInfo:
    """Return update availability without downloading or installing anything."""

    current = parse_version(current_version)
    try:
        latest = fetch_latest_release(repository, api_url=api_url, opener=opener, timeout=timeout)
    except UpdateCheckError as exc:
        return UpdateInfo(str(current_version), str(current_version), False, "", "", (), str(exc))
    available = latest.version > current
    return UpdateInfo(
        current_version=str(current_version),
        latest_version=latest.tag_name.lstrip("vV"),
        available=available,
        release_url=latest.url,
        tag_name=latest.tag_name,
        assets=latest.assets,
    )


def _host_platform() -> str:
    name = platform.system().lower()
    if name.startswith("win"):
        return "windows"
    if name == "darwin":
        return "macos"
    if name == "linux":
        return "linux"
    return name


def select_asset(
    assets: Iterable[ReleaseAsset],
    *,
    kind: str = "portable",
    platform_name: Optional[str] = None,
) -> Optional[ReleaseAsset]:
    """Select a release asset by platform and user-facing install kind.

    ``kind`` is one of ``portable``, ``installer``, ``appimage``, ``deb``, or
    ``macos``.  The selector is deliberately conservative and returns ``None``
    rather than guessing a different architecture/package.
    """

    target = (platform_name or _host_platform()).lower()
    normalized_kind = kind.lower()
    candidates = list(assets)
    if target == "windows":
        needles = {
            "portable": ("agentreins.exe",),
            "installer": ("windows-x64-setup.exe", "setup.exe"),
        }.get(normalized_kind, (normalized_kind,))
    elif target == "linux":
        needles = {
            "portable": ("x86_64.appimage",),
            "appimage": ("x86_64.appimage",),
            "deb": ("linux-amd64.deb",),
        }.get(normalized_kind, (normalized_kind,))
    elif target in {"macos", "darwin"}:
        needles = ("macos-universal.zip",) if normalized_kind in {"portable", "macos"} else (normalized_kind,)
    else:
        needles = (normalized_kind,)
    for needle in needles:
        for asset in candidates:
            if asset.name.lower().endswith(needle.lower()):
                return asset
    return None


def _asset_checksum_name(asset_name: str) -> str:
    return f"{asset_name}.sha256"


def parse_checksum(text: str, expected_name: Optional[str] = None) -> str:
    """Parse a conventional ``sha256sum`` sidecar and return lowercase hash."""

    for line in text.splitlines():
        match = _CHECKSUM_RE.match(line.strip())
        if not match:
            continue
        digest, name = match.groups()
        if expected_name is None or Path(name).name == Path(expected_name).name:
            return digest.lower()
    raise UpdateCheckError("checksum sidecar did not contain a SHA-256 entry")


def verify_sha256(path: Path, expected: str) -> None:
    expected = expected.lower().removeprefix("sha256:").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise UpdateCheckError("invalid expected SHA-256 digest")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    actual = digest.hexdigest()
    if actual != expected:
        raise UpdateCheckError(f"SHA-256 mismatch for {path.name}: expected {expected}, got {actual}")


def download_asset(
    asset: ReleaseAsset,
    destination: Path,
    *,
    expected_sha256: Optional[str] = None,
    opener: Callable[..., Any] = urlopen,
    timeout: float = 30.0,
) -> Path:
    """Download one asset atomically, requiring a digest before saving.

    The destination is never replaced until the complete response is written
    and verified.  Callers still need to validate package signatures before
    executing an installer.
    """

    if not asset.url:
        raise UpdateCheckError(f"asset {asset.name!r} has no download URL")
    if not expected_sha256:
        raise UpdateCheckError("a SHA-256 digest is required before downloading a release asset")
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Optional[Path] = None
    request = Request(asset.url, headers={"Accept": "application/octet-stream", "User-Agent": USER_AGENT})
    try:
        with opener(request, timeout=timeout) as response:
            with tempfile.NamedTemporaryFile(prefix=f".{destination.name}.", dir=destination.parent, delete=False) as handle:
                temporary = Path(handle.name)
                shutil.copyfileobj(response, handle, length=1024 * 1024)
        if expected_sha256:
            verify_sha256(temporary, expected_sha256)
        os.replace(temporary, destination)
        temporary = None
        return destination
    except HTTPError as exc:
        raise UpdateCheckError(f"download returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise UpdateCheckError(f"download failed: {exc.reason}") from exc
    except OSError as exc:
        raise UpdateCheckError(f"download failed: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def download_and_verify_release_asset(
    asset: ReleaseAsset,
    assets: Iterable[ReleaseAsset],
    destination: Path,
    *,
    opener: Callable[..., Any] = urlopen,
    timeout: float = 30.0,
) -> Path:
    """Download a release asset and verify its API digest or SHA256 sidecar.

    GitHub releases currently expose ``digest`` for some assets only. AgentReins
    therefore publishes a conventional sidecar for each binary/package. This
    helper requires one of those verification paths; it will not silently save
    an unchecked artifact.
    """

    if not asset.name or Path(asset.name).name != asset.name or "/" in asset.name or "\\" in asset.name:
        raise UpdateCheckError(f"unsafe release asset name: {asset.name!r}")
    if Path(destination).name != asset.name:
        raise UpdateCheckError("download destination must use the release asset's exact filename")
    expected = asset.digest
    if not expected:
        sidecar = next((candidate for candidate in assets if candidate.name == _asset_checksum_name(asset.name)), None)
        if sidecar is None:
            raise UpdateCheckError(f"release has no SHA-256 metadata for {asset.name}")
        request = Request(sidecar.url, headers={"Accept": "application/octet-stream", "User-Agent": USER_AGENT})
        try:
            with opener(request, timeout=timeout) as response:
                checksum_text = response.read().decode("ascii")
        except (HTTPError, URLError, OSError, UnicodeDecodeError) as exc:
            raise UpdateCheckError(f"could not fetch checksum for {asset.name}: {exc}") from exc
        expected = parse_checksum(checksum_text, asset.name)
    return download_asset(asset, destination, expected_sha256=expected, opener=opener, timeout=timeout)


def _json_output(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Check for AgentReins GitHub updates")
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--current-version", default=BUILT_VERSION)
    parser.add_argument("--api-url", default=DEFAULT_API_URL, help=argparse.SUPPRESS)
    parser.add_argument("--check", action="store_true", help="check the latest stable release (default)")
    parser.add_argument("--download", type=Path, metavar="DIR", help="download a selected asset into DIR")
    parser.add_argument("--kind", default="portable", choices=("portable", "installer", "appimage", "deb", "macos"))
    args = parser.parse_args(argv)
    info = check_for_updates(args.current_version, args.repository, api_url=args.api_url)
    if info.error:
        _json_output({"available": False, "error": info.error, "currentVersion": info.current_version})
        return 2
    output: dict[str, Any] = {
        "available": info.available,
        "currentVersion": info.current_version,
        "latestVersion": info.latest_version,
        "releaseUrl": info.release_url,
        "tag": info.tag_name,
        "assets": [asset.__dict__ for asset in info.assets],
    }
    if args.download:
        asset = select_asset(info.assets, kind=args.kind)
        if asset is None:
            _json_output({**output, "error": f"no {args.kind} asset for {_host_platform()}"})
            return 3
        try:
            downloaded = download_and_verify_release_asset(asset, info.assets, args.download / asset.name)
        except UpdateCheckError as exc:
            _json_output({**output, "error": str(exc)})
            return 4
        output["downloaded"] = str(downloaded)
    _json_output(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
