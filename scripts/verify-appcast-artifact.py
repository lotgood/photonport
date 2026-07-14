#!/usr/bin/env python3
"""Fail closed verification for a locally generated PhotonPort appcast."""

from __future__ import annotations

import argparse
import base64
import binascii
import importlib.util
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SPARKLE_NAMESPACE = "http://www.andymatuschak.org/xml-namespaces/sparkle"
SPARKLE_ED_SIGNATURE = "{" + SPARKLE_NAMESPACE + "}edSignature"
SPARKLE_SHORT_VERSION = "{" + SPARKLE_NAMESPACE + "}shortVersionString"
RELEASE_DOWNLOAD_ROOT = "https://github.com/lotgood/photonport/releases/download"
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


class VerificationError(ValueError):
    pass


def load_ed25519_verify():
    module_path = Path(__file__).resolve().parent / "evidence" / "ed25519_rfc8032.py"
    spec = importlib.util.spec_from_file_location("photonport_ed25519", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Ed25519 verifier from " + str(module_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    verify = getattr(module, "verify", None)
    if not callable(verify):
        raise RuntimeError("Ed25519 verifier has no callable verify function")
    return verify


VERIFY_ED25519 = load_ed25519_verify()


def decode_base64(value: str, label: str, expected_length: int) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise VerificationError(label + " is not valid base64") from error
    if len(decoded) != expected_length:
        raise VerificationError(label + f" must be {expected_length} bytes")
    return decoded


def verify_appcast_artifact(
    appcast: Path, dmg: Path, version: str, tag: str, public_key: str
) -> None:
    if not VERSION_PATTERN.fullmatch(version):
        raise VerificationError("version must be numeric MAJOR.MINOR.PATCH")
    expected_tag = "photonport-v" + version
    if tag != expected_tag:
        raise VerificationError("tag must exactly match " + expected_tag)

    expected_dmg = "PhotonPort-" + version + ".dmg"
    expected_url = f"{RELEASE_DOWNLOAD_ROOT}/{expected_tag}/{expected_dmg}"
    public_key_bytes = decode_base64(public_key, "Sparkle public key", 32)

    try:
        root = ET.fromstring(appcast.read_bytes())
    except ET.ParseError as error:
        raise VerificationError(f"appcast is not valid XML: {error}") from error

    enclosures = [
        element
        for element in root.iter()
        if isinstance(element.tag, str) and element.tag.rsplit("}", 1)[-1] == "enclosure"
    ]
    if len(enclosures) != 1:
        raise VerificationError("appcast must contain exactly one enclosure")
    enclosure = enclosures[0]
    if enclosure.get("url") != expected_url:
        raise VerificationError("appcast enclosure URL does not exactly match the release DMG")
    if enclosure.get(SPARKLE_SHORT_VERSION) != version:
        raise VerificationError("appcast shortVersionString does not match the release version")

    encoded_signature = enclosure.get(SPARKLE_ED_SIGNATURE)
    if encoded_signature is None:
        raise VerificationError("appcast enclosure has no Sparkle EdDSA signature")
    signature = decode_base64(encoded_signature, "Sparkle EdDSA signature", 64)
    if not VERIFY_ED25519(public_key_bytes, dmg.read_bytes(), signature):
        raise VerificationError("Sparkle EdDSA signature does not verify the local DMG")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--appcast", required=True, type=Path)
    parser.add_argument("--dmg", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--public-key", required=True)
    args = parser.parse_args()

    try:
        verify_appcast_artifact(
            args.appcast, args.dmg, args.version, args.tag, args.public_key
        )
    except (OSError, VerificationError) as error:
        print(f"appcast artifact verification failed: {error}", file=sys.stderr)
        return 1
    print(f"verified appcast artifact for {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
