import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts/provenance/audit_manifest.py"
spec = importlib.util.spec_from_file_location("audit_manifest", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ProvenanceManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "Sources").mkdir()
        (self.root / "Sources/a.swift").write_text("one\ntwo\n", encoding="utf-8")
        self.sha = hashlib.sha256((self.root / "Sources/a.swift").read_bytes()).hexdigest()
        self.base = [{"commit": "c", "tree": "t", "blob": "b", "license_sha256": "l"}]

    def tearDown(self):
        self.tmp.cleanup()

    def manifest(self, entry, shipped=None):
        return {
            "schema_version": 1,
            "shipped_paths": shipped or ["Sources/a.swift"],
            "entries": [entry],
        }

    def region(self, start, end, classification="PHOTONPORT_OWNED"):
        return {
            "output_lines": [start, end],
            "classification": classification,
            "author_evidence": "commit:x",
            "reviewer": "r",
            "reviewed_at": "2026-01-01T00:00:00Z",
            "replacement_method": "original",
        }

    def test_complete_region_manifest_passes(self):
        entry = {
            "path": "Sources/a.swift",
            "output_blob_sha256": self.sha,
            "whole_file": False,
            "regions": [self.region(1, 1), self.region(2, 2)],
        }
        self.assertEqual(mod.audit(self.manifest(entry), self.root, self.base)["errors"], [])

    def test_whole_file_passes(self):
        entry = {
            "path": "Sources/a.swift",
            "output_blob_sha256": self.sha,
            "whole_file": True,
            "classification": "PHOTONPORT_OWNED",
            "author_evidence": "x",
            "reviewer": "r",
            "reviewed_at": "2026-01-01T00:00:00Z",
            "replacement_method": "original",
        }
        self.assertTrue(mod.audit(self.manifest(entry), self.root, self.base)["ok"])

    def test_blocks_forbidden_classification(self):
        entry = {
            "path": "Sources/a.swift",
            "output_blob_sha256": self.sha,
            "regions": [self.region(1, 2, "AMBIGUOUS")],
        }
        self.assertTrue(mod.audit(self.manifest(entry), self.root, self.base)["errors"])

    def test_rejects_uncovered_lines(self):
        entry = {
            "path": "Sources/a.swift",
            "output_blob_sha256": self.sha,
            "regions": [self.region(1, 1)],
        }
        self.assertTrue(mod.audit(self.manifest(entry), self.root, self.base)["errors"])

    def test_rejects_hash_and_escape(self):
        entry = {"path": "../x", "output_blob_sha256": "0" * 64, "whole_file": True}
        errors = mod.audit(self.manifest(entry, ["../x"]), self.root, self.base)["errors"]
        self.assertTrue(any("escapes" in error for error in errors))

    def test_mit_requires_archived_license_evidence(self):
        region = self.region(1, 2, "MIT_EXACT")
        region.update(
            source_repository="u",
            source_commit="c",
            source_blob="b",
            license_spdx="MIT",
        )
        entry = {
            "path": "Sources/a.swift",
            "output_blob_sha256": self.sha,
            "regions": [region],
        }
        baseline = [{"commit": "c", "blob": "b"}]
        errors = mod.audit(self.manifest(entry), self.root, baseline)["errors"]
        self.assertTrue(any("license evidence" in error for error in errors))

    def test_rejects_missing_and_unexpected_manifest_entries(self):
        entry = {
            "path": "Sources/a.swift",
            "output_blob_sha256": self.sha,
            "whole_file": True,
            "classification": "PHOTONPORT_OWNED",
            "author_evidence": "x",
            "reviewer": "r",
            "reviewed_at": "2026-01-01T00:00:00Z",
            "replacement_method": "original",
        }
        missing = mod.audit(self.manifest(entry, ["Sources/missing.swift"]), self.root, self.base)
        self.assertTrue(any("missing manifest entries" in error for error in missing["errors"]))
        self.assertTrue(any("not declared shipped" in error for error in missing["errors"]))


if __name__ == "__main__":
    unittest.main()
