#!/usr/bin/env python3
"""Verify the release appcast before replacing the GitHub Pages feed."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import importlib.util
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

SPARKLE_ED_SIGNATURE = (
    "{http://www.andymatuschak.org/xml-namespaces/sparkle}edSignature"
)
RELEASE_OWNER = "lotgood"
RELEASE_REPOSITORY = "photonport"
RELEASE_HOST = "github.com"
RELEASE_TAG_PATTERN = re.compile(
    r"^photonport-v(?P<version>[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$"
)
PUBLIC_KEY_PATTERN = re.compile(r"^\s*SUPublicEDKey:\s*(?P<value>\S+)\s*$")
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class VerificationError(ValueError):
    pass


def _load_ed25519_verifier():
    module_path = REPOSITORY_ROOT / "scripts" / "evidence" / "ed25519_rfc8032.py"
    spec = importlib.util.spec_from_file_location("photonport_ed25519", module_path)
    if spec is None or spec.loader is None:
        raise VerificationError("cannot load Ed25519 verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify


ED25519_VERIFY = _load_ed25519_verifier()


def _expected_enclosure_url(tag: str) -> str:
    match = RELEASE_TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise VerificationError(f"invalid PhotonPort release tag: {tag}")
    version = match.group("version")
    filename = f"PhotonPort-{version}.dmg"
    return (
        f"https://{RELEASE_HOST}/{RELEASE_OWNER}/{RELEASE_REPOSITORY}"
        f"/releases/download/{tag}/{filename}"
    )


def _is_expected_enclosure_url(url: str, expected_url: str) -> bool:
    parsed = urlparse(url)
    expected = urlparse(expected_url)
    return (
        parsed.scheme == "https"
        and parsed.netloc == RELEASE_HOST
        and parsed.path == expected.path
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
        and url == expected_url
    )


def _read_public_key(project: Path) -> bytes:
    try:
        lines = project.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise VerificationError(f"cannot read project public key: {error}") from error

    encoded_key = next(
        (
            match.group("value")
            for line in lines
            if (match := PUBLIC_KEY_PATTERN.fullmatch(line)) is not None
        ),
        None,
    )
    if encoded_key is None:
        raise VerificationError("project.yml has no SUPublicEDKey")
    try:
        public_key = base64.b64decode(encoded_key, validate=True)
    except (ValueError, binascii.Error) as error:
        raise VerificationError("project.yml SUPublicEDKey is not base64") from error
    if len(public_key) != 32:
        raise VerificationError("project.yml SUPublicEDKey is not 32 bytes")
    return public_key


def _read_dmg(dmg: Path | None, enclosure_url: str) -> bytes:
    if dmg is not None:
        return dmg.read_bytes()
    request = urllib.request.Request(
        enclosure_url,
        headers={"User-Agent": "PhotonPort-pages-appcast-verifier"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except OSError as error:
        raise VerificationError(f"cannot download release DMG: {error}") from error


def verify_appcast(
    appcast: Path,
    checksum: Path,
    tag: str,
    *,
    dmg: Path | None = None,
    public_key: bytes | None = None,
    project: Path = REPOSITORY_ROOT / "project.yml",
) -> None:
    payload = appcast.read_bytes()
    checksum_fields = checksum.read_text(encoding="utf-8").split()
    if (
        not checksum_fields
        or not re.fullmatch(r"[0-9a-fA-F]{64}", checksum_fields[0])
    ):
        raise VerificationError("appcast checksum file has no SHA-256 digest")
    actual = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(checksum_fields[0].lower(), actual):
        raise VerificationError("appcast SHA-256 mismatch")

    try:
        root = ET.fromstring(payload)
    except ET.ParseError as error:
        raise VerificationError(f"appcast is not valid XML: {error}") from error

    expected_url = _expected_enclosure_url(tag)
    enclosures = [
        candidate
        for candidate in root.iter()
        if candidate.tag.rsplit("}", 1)[-1] == "enclosure"
        and _is_expected_enclosure_url(candidate.attrib.get("url", ""), expected_url)
    ]
    if len(enclosures) != 1:
        raise VerificationError(
            "appcast must have exactly one enclosure for the selected release asset"
        )
    encoded_signature = enclosures[0].attrib.get(SPARKLE_ED_SIGNATURE)
    if encoded_signature is None:
        raise VerificationError(
            "selected appcast enclosure has no Sparkle EdDSA signature"
        )
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
    except (ValueError, binascii.Error) as error:
        raise VerificationError("appcast Sparkle EdDSA signature is not base64") from error
    if len(signature) != 64:
        raise VerificationError("appcast Sparkle EdDSA signature is not 64 bytes")

    if public_key is None:
        public_key = _read_public_key(project)
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise VerificationError("Sparkle EdDSA public key is not 32 bytes")
    if not ED25519_VERIFY(public_key, _read_dmg(dmg, expected_url), signature):
        raise VerificationError("appcast Sparkle EdDSA signature does not verify the DMG")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--appcast", required=True, type=Path)
    parser.add_argument("--checksum", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument(
        "--dmg",
        type=Path,
        help="downloaded release DMG; defaults to the verified enclosure URL",
    )
    parser.add_argument("--project", type=Path, default=REPOSITORY_ROOT / "project.yml")
    args = parser.parse_args()

    try:
        verify_appcast(
            args.appcast,
            args.checksum,
            args.tag,
            dmg=args.dmg,
            project=args.project,
        )
    except (OSError, VerificationError) as error:
        print(f"pages appcast verification failed: {error}", file=sys.stderr)
        return 1
    print(f"verified Pages appcast for {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
