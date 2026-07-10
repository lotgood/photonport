#!/usr/bin/env python3
"""Select the appcast asset that a Pages deployment must preserve."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

TAG_PATTERN = re.compile(
    r"^photonport-v(?P<major>[0-9]+)\."
    r"(?P<minor>[0-9]+)\."
    r"(?P<patch>[0-9]+)"
    r"(?:-(?P<prerelease>[0-9A-Za-z.-]+))?"
    r"(?:\+(?P<build>[0-9A-Za-z.-]+))?$"
)


class SelectionError(ValueError):
    pass

def _version_key(tag: str) -> tuple[Any, ...]:
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise SelectionError(f"invalid PhotonPort release tag: {tag}")
    prerelease = match.group("prerelease")
    prerelease_key = tuple(
        (0, int(part)) if part.isdigit() else (1, part)
        for part in (prerelease or "").split(".")
        if part
    )
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        1 if prerelease is None else 0,
        prerelease_key,
    )


def _published_namespaced(releases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    eligible = [
        release
        for release in releases
        if not release.get("draft", False)
        and not release.get("prerelease", False)
        and release.get("published_at")
        and TAG_PATTERN.fullmatch(str(release.get("tag_name", "")))
    ]
    return sorted(
        eligible,
        key=lambda release: (
            _version_key(str(release["tag_name"])),
            str(release["published_at"]),
        ),
        reverse=True,
    )


def _appcast_selection(release: dict[str, Any]) -> dict[str, str]:
    tag = str(release.get("tag_name", ""))
    assets = {
        str(asset.get("name")): str(asset.get("browser_download_url"))
        for asset in release.get("assets", [])
        if asset.get("name") and asset.get("browser_download_url")
    }
    missing = [
        name
        for name in ("appcast.xml", "appcast.xml.sha256")
        if name not in assets
    ]
    if missing:
        raise SelectionError(
            f"published PhotonPort release {tag} is missing: {', '.join(missing)}"
        )
    return {
        "mode": "appcast",
        "tag": tag,
        "url": assets["appcast.xml"],
        "checksum_url": assets["appcast.xml.sha256"],
    }


def select_appcast(
    *,
    event: str,
    releases: list[dict[str, Any]],
    release_tag: str = "",
    dispatch_tag: str = "",
) -> dict[str, str]:
    published = _published_namespaced(releases)

    if event == "workflow_dispatch":
        if not TAG_PATTERN.fullmatch(dispatch_tag):
            raise SelectionError(
                "workflow_dispatch tag must be a namespaced PhotonPort release tag"
            )
        match = next(
            (release for release in published if release.get("tag_name") == dispatch_tag),
            None,
        )
        if match is None:
            raise SelectionError(f"published PhotonPort release not found: {dispatch_tag}")
        return _appcast_selection(match)

    if event == "release" and TAG_PATTERN.fullmatch(release_tag):
        match = next(
            (release for release in published if release.get("tag_name") == release_tag),
            None,
        )
        if match is None:
            raise SelectionError(f"published PhotonPort release not found: {release_tag}")
        return _appcast_selection(match)

    if not published:
        return {"mode": "privacy-only", "tag": "", "url": "", "checksum_url": ""}
    return _appcast_selection(published[0])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--event",
        required=True,
        choices=("push", "release", "workflow_dispatch"),
    )
    parser.add_argument("--release-tag", default="")
    parser.add_argument("--dispatch-tag", default="")
    parser.add_argument("--releases-json", required=True, type=Path)
    args = parser.parse_args()

    try:
        releases = json.loads(args.releases_json.read_text(encoding="utf-8"))
        if not isinstance(releases, list):
            raise SelectionError("GitHub releases response must be a JSON array")
        selection = select_appcast(
            event=args.event,
            releases=releases,
            release_tag=args.release_tag,
            dispatch_tag=args.dispatch_tag,
        )
    except (OSError, json.JSONDecodeError, SelectionError) as error:
        print(f"pages appcast selection failed: {error}", file=sys.stderr)
        return 1

    print(json.dumps(selection, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
