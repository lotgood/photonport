#!/usr/bin/env python3
import base64
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "select-pages-appcast.py"
SPEC = importlib.util.spec_from_file_location("pages_appcast", MODULE_PATH)
assert SPEC and SPEC.loader
pages_appcast = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pages_appcast)
VERIFY_PATH = Path(__file__).parents[1] / "scripts" / "verify-pages-appcast.py"
VERIFY_SPEC = importlib.util.spec_from_file_location(
    "verify_pages_appcast", VERIFY_PATH
)
assert VERIFY_SPEC and VERIFY_SPEC.loader
verify_pages_appcast = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(verify_pages_appcast)


def release(
    tag,
    published_at,
    *,
    appcast=True,
    checksum=True,
    draft=False,
    prerelease=False,
):
    assets = []
    if appcast:
        assets.append(
            {
                "name": "appcast.xml",
                "browser_download_url": f"https://downloads.example/{tag}/appcast.xml",
            }
        )
        if checksum:
            assets.append(
                {
                    "name": "appcast.xml.sha256",
                    "browser_download_url": (
                        f"https://downloads.example/{tag}/appcast.xml.sha256"
                    ),
                }
            )
    return {
        "tag_name": tag,
        "published_at": published_at,
        "draft": draft,
        "prerelease": prerelease,
        "assets": assets,
    }


def appcast_files(directory, tag="photonport-v0.1.0"):
    signature = base64.b64encode(bytes(range(64))).decode("ascii")
    payload = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">'
        '<channel><item><enclosure '
        f'url="https://downloads.example/{tag}/PhotonPort.dmg" '
        f'sparkle:edSignature="{signature}" /></item></channel></rss>'
    ).encode("utf-8")
    appcast = Path(directory) / "appcast.xml"
    checksum = Path(directory) / "appcast.xml.sha256"
    appcast.write_bytes(payload)
    checksum.write_text(
        f"{hashlib.sha256(payload).hexdigest()}  appcast.xml\n",
        encoding="utf-8",
    )
    return appcast, checksum


class PagesAppcastSelectionTests(unittest.TestCase):
    def test_first_push_is_privacy_only(self):
        self.assertEqual(
            pages_appcast.select_appcast(event="push", releases=[]),
            {"mode": "privacy-only", "tag": "", "url": "", "checksum_url": ""},
        )

    def test_push_preserves_latest_namespaced_release(self):
        releases = [
            release("photonport-v0.1.0", "2026-01-01T00:00:00Z"),
            release("photonport-v0.2.0", "2026-02-01T00:00:00Z"),
        ]
        selected = pages_appcast.select_appcast(event="push", releases=releases)
        self.assertEqual(selected["tag"], "photonport-v0.2.0")

    def test_push_prefers_highest_version_over_latest_publish_time(self):
        releases = [
            release("photonport-v0.2.0", "2026-01-01T00:00:00Z"),
            release("photonport-v0.1.0", "2026-03-01T00:00:00Z"),
        ]
        selected = pages_appcast.select_appcast(event="push", releases=releases)
        self.assertEqual(selected["tag"], "photonport-v0.2.0")

    def test_push_prefers_stable_release_over_prerelease(self):
        releases = [
            release("photonport-v0.2.0-rc.1", "2026-03-01T00:00:00Z"),
            release("photonport-v0.2.0", "2026-01-01T00:00:00Z"),
        ]
        selected = pages_appcast.select_appcast(event="push", releases=releases)
        self.assertEqual(selected["tag"], "photonport-v0.2.0")

    def test_push_orders_numeric_prerelease_identifiers_numerically(self):
        releases = [
            release("photonport-v0.2.0-alpha.2", "2026-03-01T00:00:00Z"),
            release("photonport-v0.2.0-alpha.10", "2026-01-01T00:00:00Z"),
        ]
        selected = pages_appcast.select_appcast(event="push", releases=releases)
        self.assertEqual(selected["tag"], "photonport-v0.2.0-alpha.10")

    def test_push_excludes_github_prereleases_from_stable_feed(self):
        releases = [
            release(
                "photonport-v0.3.0-rc.1",
                "2026-03-01T00:00:00Z",
                prerelease=True,
            ),
            release("photonport-v0.2.0", "2026-01-01T00:00:00Z"),
        ]
        selected = pages_appcast.select_appcast(event="push", releases=releases)
        self.assertEqual(selected["tag"], "photonport-v0.2.0")

    def test_non_photon_release_preserves_latest_photonport_feed(self):
        releases = [
            release("v9.9.9", "2026-03-01T00:00:00Z"),
            release("photonport-v0.2.0", "2026-02-01T00:00:00Z"),
        ]
        selected = pages_appcast.select_appcast(
            event="release", releases=releases, release_tag="v9.9.9"
        )
        self.assertEqual(selected["tag"], "photonport-v0.2.0")

    def test_only_non_photon_releases_keeps_privacy_only(self):
        releases = [release("v9.9.9", "2026-03-01T00:00:00Z")]
        selected = pages_appcast.select_appcast(event="push", releases=releases)
        self.assertEqual(selected["mode"], "privacy-only")

    def test_namespaced_release_selects_event_release(self):
        releases = [
            release("photonport-v0.2.0", "2026-02-01T00:00:00Z"),
            release("photonport-v0.1.0", "2026-01-01T00:00:00Z"),
        ]
        selected = pages_appcast.select_appcast(
            event="release",
            releases=releases,
            release_tag="photonport-v0.1.0",
        )
        self.assertEqual(selected["tag"], "photonport-v0.1.0")

    def test_namespaced_release_event_missing_from_api_fails_closed(self):
        with self.assertRaises(pages_appcast.SelectionError):
            pages_appcast.select_appcast(
                event="release",
                releases=[],
                release_tag="photonport-v0.1.0",
            )

    def test_dispatch_selects_exact_published_release(self):
        releases = [release("photonport-v0.1.0", "2026-01-01T00:00:00Z")]
        selected = pages_appcast.select_appcast(
            event="workflow_dispatch",
            releases=releases,
            dispatch_tag="photonport-v0.1.0",
        )
        self.assertEqual(selected["tag"], "photonport-v0.1.0")

    def test_dispatch_rejects_invalid_tag(self):
        with self.assertRaises(pages_appcast.SelectionError):
            pages_appcast.select_appcast(
                event="workflow_dispatch", releases=[], dispatch_tag="v0.1.0"
            )

    def test_dispatch_rejects_missing_release(self):
        with self.assertRaises(pages_appcast.SelectionError):
            pages_appcast.select_appcast(
                event="workflow_dispatch",
                releases=[],
                dispatch_tag="photonport-v0.1.0",
            )

    def test_existing_release_without_appcast_fails_closed(self):
        releases = [
            release("photonport-v0.1.0", "2026-01-01T00:00:00Z", appcast=False)
        ]
        with self.assertRaises(pages_appcast.SelectionError):
            pages_appcast.select_appcast(event="push", releases=releases)

    def test_existing_release_without_checksum_fails_closed(self):
        releases = [
            release(
                "photonport-v0.1.0",
                "2026-01-01T00:00:00Z",
                checksum=False,
            )
        ]
        with self.assertRaises(pages_appcast.SelectionError):
            pages_appcast.select_appcast(event="push", releases=releases)

    def test_draft_release_is_not_used(self):
        releases = [
            release(
                "photonport-v0.1.0",
                "2026-01-01T00:00:00Z",
                draft=True,
            )
        ]
        selected = pages_appcast.select_appcast(event="push", releases=releases)
        self.assertEqual(selected["mode"], "privacy-only")

    def test_appcast_artifact_verifier_accepts_matching_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            appcast, checksum = appcast_files(directory)
            verify_pages_appcast.verify_appcast(
                appcast, checksum, "photonport-v0.1.0"
            )

    def test_appcast_artifact_verifier_rejects_wrong_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            appcast, checksum = appcast_files(directory)
            checksum.write_text(f"{'0' * 64}  appcast.xml\n", encoding="utf-8")
            with self.assertRaises(verify_pages_appcast.VerificationError):
                verify_pages_appcast.verify_appcast(
                    appcast, checksum, "photonport-v0.1.0"
                )

    def test_appcast_artifact_verifier_rejects_wrong_release_tag(self):
        with tempfile.TemporaryDirectory() as directory:
            appcast, checksum = appcast_files(directory)
            with self.assertRaises(verify_pages_appcast.VerificationError):
                verify_pages_appcast.verify_appcast(
                    appcast, checksum, "photonport-v9.9.9"
                )

    def test_appcast_artifact_verifier_rejects_malformed_xml(self):
        with tempfile.TemporaryDirectory() as directory:
            appcast, checksum = appcast_files(directory)
            payload = b"<rss>"
            appcast.write_bytes(payload)
            checksum.write_text(
                f"{hashlib.sha256(payload).hexdigest()}  appcast.xml\n",
                encoding="utf-8",
            )
            with self.assertRaises(verify_pages_appcast.VerificationError):
                verify_pages_appcast.verify_appcast(
                    appcast, checksum, "photonport-v0.1.0"
                )

    def test_appcast_artifact_verifier_rejects_missing_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            appcast, checksum = appcast_files(directory)
            payload = appcast.read_bytes().replace(
                b"sparkle:edSignature", b"sparkle:other"
            )
            appcast.write_bytes(payload)
            checksum.write_text(
                f"{hashlib.sha256(payload).hexdigest()}  appcast.xml\n",
                encoding="utf-8",
            )
            with self.assertRaises(verify_pages_appcast.VerificationError):
                verify_pages_appcast.verify_appcast(
                    appcast, checksum, "photonport-v0.1.0"
                )

    def test_appcast_artifact_verifier_rejects_short_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            appcast, checksum = appcast_files(directory)
            full_signature = base64.b64encode(bytes(range(64)))
            short_signature = base64.b64encode(bytes(range(32)))
            payload = appcast.read_bytes().replace(full_signature, short_signature)
            appcast.write_bytes(payload)
            checksum.write_text(
                f"{hashlib.sha256(payload).hexdigest()}  appcast.xml\n",
                encoding="utf-8",
            )
            with self.assertRaises(verify_pages_appcast.VerificationError):
                verify_pages_appcast.verify_appcast(
                    appcast, checksum, "photonport-v0.1.0"
                )


if __name__ == "__main__":
    unittest.main()
