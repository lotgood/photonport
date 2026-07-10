#!/usr/bin/env python3
"""Verify the release appcast before replacing the GitHub Pages feed."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SPARKLE_ED_SIGNATURE = (
    "{http://www.andymatuschak.org/xml-namespaces/sparkle}edSignature"
)


class VerificationError(ValueError):
    pass


def verify_appcast(appcast: Path, checksum: Path, tag: str) -> None:
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

    enclosure = next(
        (
            candidate
            for candidate in root.iter()
            if candidate.tag.rsplit("}", 1)[-1] == "enclosure"
            and f"/{tag}/" in candidate.attrib.get("url", "")
        ),
        None,
    )
    if enclosure is None:
        raise VerificationError(
            "appcast has no enclosure for the selected release tag"
        )
    encoded_signature = enclosure.attrib.get(SPARKLE_ED_SIGNATURE)
    if encoded_signature is None:
        raise VerificationError(
            "selected appcast enclosure has no Sparkle EdDSA signature"
        )
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
    except ValueError as error:
        raise VerificationError("appcast Sparkle EdDSA signature is not base64") from error
    if len(signature) != 64:
        raise VerificationError("appcast Sparkle EdDSA signature is not 64 bytes")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--appcast", required=True, type=Path)
    parser.add_argument("--checksum", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()

    try:
        verify_appcast(args.appcast, args.checksum, args.tag)
    except (OSError, VerificationError) as error:
        print(f"pages appcast verification failed: {error}", file=sys.stderr)
        return 1
    print(f"verified Pages appcast for {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
