#!/usr/bin/env python3
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "provenance" / "scan_forbidden.py"
SPEC = importlib.util.spec_from_file_location("scan_forbidden", MODULE_PATH)
assert SPEC and SPEC.loader
scan_forbidden = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan_forbidden)


class ForbiddenScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.repo = base / "upstream"
        self.root = base / "shipped"
        self.repo.mkdir()
        self.root.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        (self.repo / "source.txt").write_text("one\ntwo\nthree\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()
        (self.repo / "source.txt").write_text("one\ntwo\nforbidden addition\nthree\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "change")
        self.head = self.git("rev-parse", "HEAD").strip()

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True)

    def run_scan(self, content, name="main.txt"):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        exact = self.root / "exact.json"
        review = self.root / "review.json"
        result = scan_forbidden.scan(self.root, self.repo, f"{self.base}..{self.head}", exact, review)
        return result

    def test_exact_blob_match(self):
        exact, _ = self.run_scan("one\ntwo\nforbidden addition\nthree\n")
        self.assertTrue(any(item["kind"] == "blob" for item in exact["forbidden"]))

    def test_normalized_hunk_match(self):
        exact, _ = self.run_scan("one\n  forbidden addition  \nthree\n")
        self.assertTrue(any(item["kind"] == "hunk" for item in exact["forbidden"]))

    def test_similarity_is_manual_review(self):
        _, review = self.run_scan("unrelated prefix forbidden addition suffix\n")
        self.assertTrue(review["manual_review"])
        self.assertIn("score", review["manual_review"][0])

    def test_clean_input(self):
        exact, review = self.run_scan("a completely unrelated short file\n")
        self.assertEqual(exact["forbidden"], [])
        self.assertEqual(review["manual_review"], [])

    def test_exclusions_and_outputs(self):
        (self.root / ".git").mkdir()
        (self.root / ".git" / "hidden.txt").write_text("one\ntwo\nforbidden addition\nthree\n", encoding="utf-8")
        (self.root / "build").mkdir()
        (self.root / "build" / "generated.txt").write_text("one\ntwo\nforbidden addition\nthree\n", encoding="utf-8")
        (self.root / "exact.json").write_text("one\ntwo\nforbidden addition\nthree\n", encoding="utf-8")
        exact, _ = self.run_scan("ordinary content\n")
        self.assertEqual(exact["forbidden"], [])

    def test_cli_fails_when_exact_matches_are_found(self):
        (self.root / "main.txt").write_text(
            "one\ntwo\nforbidden addition\nthree\n", encoding="utf-8"
        )
        result = scan_forbidden.main([
            "--root", str(self.root),
            "--upstream-cache", str(self.repo),
            "--forbidden-range", f"{self.base}..{self.head}",
            "--exact-output", str(self.root / "exact.json"),
            "--review-output", str(self.root / "review.json"),
        ])
        self.assertEqual(result, 2)
        self.assertTrue(json.loads((self.root / "exact.json").read_text())["forbidden"])
    def test_added_blob_range_is_supported(self):
        (self.repo / "added.txt").write_text("new upstream text\n", encoding="utf-8")
        self.git("add", "added.txt")
        self.git("commit", "-qm", "add file")
        added_head = self.git("rev-parse", "HEAD").strip()
        exact, review = scan_forbidden.scan(
            self.root,
            self.repo,
            f"{self.head}..{added_head}",
            self.root / "added-exact.json",
            self.root / "added-review.json",
        )
        self.assertEqual(exact["forbidden"], [])
        self.assertEqual(review["manual_review"], [])
    def test_binary_upstream_blob_is_skipped_for_similarity(self):
        (self.repo / "image.bin").write_bytes(b"\x89PNG\r\n\x1a\n\xff")
        self.git("add", "image.bin")
        self.git("commit", "-qm", "add binary")
        binary_head = self.git("rev-parse", "HEAD").strip()
        exact, review = scan_forbidden.scan(
            self.root,
            self.repo,
            f"{self.head}..{binary_head}",
            self.root / "binary-exact.json",
            self.root / "binary-review.json",
        )
        self.assertEqual(exact["forbidden"], [])
        self.assertEqual(review["manual_review"], [])
    def test_invalid_range_fails_closed(self):
        with self.assertRaises(scan_forbidden.ScanError):
            scan_forbidden.scan(self.root, self.repo, "does-not-exist..also-missing", self.root / "e", self.root / "r")


if __name__ == "__main__":
    unittest.main()
