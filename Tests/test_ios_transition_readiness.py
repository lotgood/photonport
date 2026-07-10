import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("transition", HERE / "scripts/verify-ios-transition-readiness.py")
transition = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transition)


class TransitionReadinessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.mac, self.ios, self.protocol = (self.root / n for n in ("mac", "ios", "protocol"))
        (self.mac / "iOS").mkdir(parents=True)
        (self.ios).mkdir()
        (self.protocol).mkdir()
        (self.mac / "project.yml").write_text("targets:\n  OpenSidecariOS:\n", encoding="utf-8")
        (self.mac / "iOS/PhoneReceiver.swift").write_text("// preserved\n", encoding="utf-8")
        for name in ("LICENSE", "NOTICE.md", "PROVENANCE.yml", "project.yml"):
            (self.ios / name).write_text("standalone\n", encoding="utf-8")
        for name in ("LICENSE", "COMPATIBILITY.json"):
            (self.protocol / name).write_text("standalone\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=self.mac, check=True)
        subprocess.run(["git", "-c", "user.email=test@example.invalid", "-c", "user.name=test", "add", "."], cwd=self.mac, check=True)
        subprocess.run(["git", "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-qm", "preserve"], cwd=self.mac, check=True)
        self.template = self.root / "template.json"
        self.template.write_text(json.dumps({"standalone": {"ios": ["LICENSE", "NOTICE.md", "PROVENANCE.yml", "project.yml"], "protocol": ["LICENSE", "COMPATIBILITY.json"]}}), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def write_receipt(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def args(self, **kwargs):
        base = dict(mac_root=self.mac, ios_root=self.ios, protocol_root=self.protocol,
                    g004_automated=None, g004_physical=None, g006_provenance=None,
                    export_review=None, apple_distribution=None, rollback_build=None,
                    template=self.template)
        base.update(kwargs)
        return type("Args", (), base)()

    def test_preserved_history_and_missing_receipts_block(self):
        result = transition.verify(self.args())
        self.assertFalse(result["retirementReady"])
        self.assertIn("g004", {b["category"] for b in result["blockers"]})

    def test_missing_history_blocks(self):
        (self.mac / "iOS/PhoneReceiver.swift").unlink()
        result = transition.verify(self.args())
        self.assertIn("history", {b["category"] for b in result["blockers"]})

    def test_physical_not_run_blocks(self):
        physical = self.write_receipt("physical.json", {"result": "not_run", "scenarios": []})
        automated = self.write_receipt("auto.json", {"result": "passed"})
        result = transition.verify(self.args(g004_automated=automated, g004_physical=physical))
        self.assertIn("g004", {b["category"] for b in result["blockers"]})

    def test_fully_ready_synthetic_success(self):
        auto = self.write_receipt("auto.json", {"result": "passed"})
        physical = self.write_receipt("physical.json", {"result": "passed", "scenarios": [
            {"status": "passed", "os_major": "27", "physical": True, "transport": "usb"},
            {"status": "passed", "os_major": "27", "physical": True, "transport": "wifi"}]})
        kwargs = dict(g004_automated=auto, g004_physical=physical,
            g006_provenance=self.write_receipt("g006.json", {"result": "passed"}),
            export_review=self.write_receipt("export.json", {"result": "passed", "independent": True}),
            apple_distribution=self.write_receipt("apple.json", {"result": "passed", "credentials": True, "signing": True, "testflight": True, "publication": True}),
            rollback_build=self.write_receipt("rollback.json", {"result": "passed"}))
        self.assertTrue(transition.verify(self.args(**kwargs))["retirementReady"])


if __name__ == "__main__":
    unittest.main()
