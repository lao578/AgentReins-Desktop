#!/usr/bin/env python3
"""Validate release tags before a distribution workflow publishes artifacts.

The release jobs are intentionally triggered by a broad ``v*`` tag pattern so
that GitHub can dispatch them.  This small, dependency-free gate narrows that
pattern to semantic versions and makes sure the changelog contains a matching
heading.  Keeping the rule in Python lets the macOS, Windows, and Linux jobs
share exactly the same validation instead of maintaining subtly different
shell regular expressions.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


# We publish MAJOR.MINOR.PATCH tags.  A prerelease suffix is allowed for alpha,
# beta, and release-candidate builds; build metadata is intentionally omitted
# because it does not identify a separately supported release channel here.
TAG_RE = re.compile(
    r"^v(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))"
    r"(?P<prerelease>-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


class ReleaseContractError(ValueError):
    """Raised when a tag cannot be published safely."""


def validate_release_tag(tag: str, changelog: str) -> tuple[str, str]:
    """Return ``(version, channel)`` after validating *tag* and *changelog*.

    ``channel`` is ``"prerelease"`` when the semantic version has a suffix and
    ``"stable"`` otherwise.  The changelog heading check deliberately accepts
    a date or other text after the closing bracket, while requiring the exact
    version at the beginning of the heading.
    """

    candidate = str(tag or "").strip()
    match = TAG_RE.fullmatch(candidate)
    if not match:
        raise ReleaseContractError(
            f"invalid release tag {candidate!r}; expected vMAJOR.MINOR.PATCH[-suffix]"
        )
    # The complete numeric version is captured as one group so it can be
    # compared to the changelog heading without dropping minor/patch fields.
    version = match.group("version")
    # The version includes the prerelease suffix in the tag.  Keep the lookup
    # exact so v1.2.3-alpha cannot accidentally match a stable v1.2.3 note.
    full_version = version + (match.group("prerelease") or "")
    version_heading = re.compile(
        rf"^##\s+\[{re.escape(full_version)}\](?:\s|$)",
        re.MULTILINE,
    )
    if not version_heading.search(str(changelog)):
        raise ReleaseContractError(
            f"CHANGELOG.md has no heading for [{full_version}]"
        )
    return full_version, (
        "prerelease" if match.group("prerelease") else "stable"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Git tag, for example v0.2.0-alpha")
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    args = parser.parse_args(argv)
    try:
        changelog = args.changelog.read_text(encoding="utf-8")
        version, channel = validate_release_tag(args.tag, changelog)
    except (OSError, ReleaseContractError) as exc:
        print(f"release contract failed: {exc}", file=sys.stderr)
        return 2
    print(f"release contract passed: {args.tag} -> {version} ({channel})")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by workflow invocation
    raise SystemExit(main())
