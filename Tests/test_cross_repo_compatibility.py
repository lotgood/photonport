import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-cross-repo-compatibility.py"
MANIFEST = {"protocol": "3.0.0", "pairing": "2.0.0", "mac": {"minimum": "0.1.0"}, "ios": {"minimum": "1.0.0"}, "mismatch": "fail_closed_with_upgrade_message"}

class CrossRepoCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.roots = [base / n for n in ("mac", "ios", "protocol")]
        for root in self.roots:
            root.mkdir(); (root / "COMPATIBILITY.json").write_text(json.dumps(MANIFEST), encoding="utf-8")
        (self.roots[0] / "project.yml").write_text('MARKETING_VERSION: "0.1.0"\n', encoding="utf-8")
        (self.roots[0] / "Main.swift").write_text('static let version = 3 static let version = 2 PhotonPort-primary-v3 PhotonPort-pair-v2\n', encoding="utf-8")
        (self.roots[1] / "project.yml").write_text('MARKETING_VERSION: "1.0.0"\n', encoding="utf-8")
        (self.roots[1] / "Main.swift").write_text('static let version = 3 static let version = 2 PhotonPort-primary-v3 PhotonPort-pair-v2\n', encoding="utf-8")
        (self.roots[2] / "spec").mkdir(); (self.roots[2] / "vectors").mkdir(); (self.roots[2] / "schemas").mkdir()
        (self.roots[2] / "spec" / "session.md").write_text("session v3", encoding="utf-8")
        (self.roots[2] / "vectors" / "pairing-v2.json").write_text(json.dumps({"version": "2.0.0"}), encoding="utf-8")
        (self.roots[2] / "vectors" / "session-v3.json").write_text(json.dumps({"version": "3.0.0"}), encoding="utf-8")
        (self.roots[2] / "schemas" / "wire.json").write_text("{}", encoding="utf-8")

    def tearDown(self): self.tmp.cleanup()

    def run_verifier(self):
        output = Path(self.tmp.name) / "artifacts" / "receipt.json"
        return subprocess.run([sys.executable, str(SCRIPT), "--mac-root", str(self.roots[0]), "--ios-root", str(self.roots[1]), "--protocol-root", str(self.roots[2]), "--output", str(output)], capture_output=True, text=True), output

    def test_success_and_stable_output(self):
        first, output = self.run_verifier(); self.assertEqual(first.returncode, 0)
        first_bytes = output.read_bytes()
        second, _ = self.run_verifier(); self.assertEqual(second.returncode, 0)
        self.assertEqual(first_bytes, output.read_bytes())
        self.assertEqual(json.loads(output.read_text())["result"], "compatible")

    def test_manifest_drift_missing_and_malformed_fail_closed(self):
        for value in ({**MANIFEST, "protocol": "9.0.0"}, {k: v for k, v in MANIFEST.items() if k != "pairing"}, "{"):
            (self.roots[1] / "COMPATIBILITY.json").write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
            result, _ = self.run_verifier(); self.assertNotEqual(result.returncode, 0); self.assertIn("FAIL_CLOSED", result.stderr)
            (self.roots[1] / "COMPATIBILITY.json").write_text(json.dumps(MANIFEST), encoding="utf-8")

    def test_source_constant_mismatch_fail_closed(self):
        (self.roots[0] / "Main.swift").write_text("protocol v3 required", encoding="utf-8")
        result, _ = self.run_verifier(); self.assertNotEqual(result.returncode, 0); self.assertIn("FAIL_CLOSED", result.stderr)

if __name__ == "__main__": unittest.main()
