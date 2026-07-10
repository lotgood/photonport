#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "provenance" / "archive_baselines.py"
SPEC = importlib.util.spec_from_file_location("archive_baselines", MODULE_PATH)
assert SPEC and SPEC.loader
archive_baselines = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive_baselines)

MIT = b'''MIT License\n\nCopyright (c) 2026 Example\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the "Software"), to deal\nin the Software without restriction, including without limitation the rights\nto use, copy, modify, merge, publish, distribute, sublicense, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all\ncopies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\nSOFTWARE.\n'''


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=repo).decode().strip()


class ArchiveBaselinesTests(unittest.TestCase):
    def make_repo(self, license_bytes=MIT):
        directory = tempfile.TemporaryDirectory()
        repo = Path(directory.name)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / "LICENSE").write_bytes(license_bytes)
        (repo / "file").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "first"], cwd=repo, check=True)
        anchor = git(repo, "rev-parse", "HEAD")
        (repo / "file").write_text("two\n", encoding="utf-8")
        subprocess.run(["git", "add", "file"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "second"], cwd=repo, check=True)
        through = git(repo, "rev-parse", "HEAD")
        return directory, repo, anchor, through

    def test_valid_mit_evidence_is_complete(self):
        holder, repo, anchor, through = self.make_repo()
        try:
            report = archive_baselines.archive(str(repo), anchor, through, repo / "out.json")
            self.assertEqual(report["anchor"], anchor)
            self.assertEqual(report["through"], through)
            self.assertEqual(len(report["commits"]), 2)
            self.assertTrue(all(item["license_classification"] == "MIT_EXACT" for item in report["commits"]))
            license_sha = git(repo, "rev-parse", f"{anchor}:LICENSE")
            self.assertEqual(report["commits"][0]["license_sha1"], license_sha)
            self.assertEqual(report["commits"][0]["license_sha256"], hashlib.sha256(MIT).hexdigest())
        finally:
            holder.cleanup()

    def test_merged_optional_commits_are_archived(self):
        holder, repo, _, anchor = self.make_repo()
        try:
            subprocess.run(["git", "checkout", "-qb", "feature"], cwd=repo, check=True)
            feature_commits = []
            for value in ("feature-one\n", "feature-two\n"):
                (repo / "feature").write_text(value, encoding="utf-8")
                subprocess.run(["git", "add", "feature"], cwd=repo, check=True)
                subprocess.run(["git", "commit", "-qm", value.strip()], cwd=repo, check=True)
                feature_commits.append(git(repo, "rev-parse", "HEAD"))
            subprocess.run(["git", "checkout", "-q", "main"], cwd=repo, check=True)
            subprocess.run(
                ["git", "merge", "-q", "--no-ff", "feature", "-m", "merge feature"],
                cwd=repo,
                check=True,
            )
            through = git(repo, "rev-parse", "HEAD")
            report = archive_baselines.archive(
                str(repo), anchor, through, repo / "merged.json"
            )
            archived = [item["commit_sha1"] for item in report["commits"]]
            self.assertEqual(archived[0], anchor)
            self.assertEqual(archived[-1], through)
            self.assertTrue(set(feature_commits).issubset(archived))
            self.assertTrue(all(item["author_date"] for item in report["commits"]))
        finally:
            holder.cleanup()
    def test_non_mit_license_blocks_without_output(self):
        holder, repo, anchor, through = self.make_repo(b"not a license\n")
        try:
            with self.assertRaises(archive_baselines.ArchiveError):
                archive_baselines.archive(str(repo), anchor, through, repo / "out.json")
            self.assertFalse((repo / "out.json").exists())
        finally:
            holder.cleanup()

    def test_missing_commit_and_invalid_range_fail_closed(self):
        holder, repo, anchor, through = self.make_repo()
        try:
            with self.assertRaises(archive_baselines.ArchiveError):
                archive_baselines.archive(str(repo), "0" * 40, through, repo / "missing.json")
            with self.assertRaises(archive_baselines.ArchiveError):
                archive_baselines.archive(str(repo), through, anchor, repo / "range.json")
        finally:
            holder.cleanup()

    def test_output_is_deterministic(self):
        holder, repo, anchor, through = self.make_repo()
        try:
            first = repo / "first.json"
            second = repo / "second.json"
            archive_baselines.archive(str(repo), anchor, through, first)
            archive_baselines.archive(str(repo), anchor, through, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(json.loads(first.read_text()), json.loads(second.read_text()))
        finally:
            holder.cleanup()


if __name__ == "__main__":
    unittest.main()
