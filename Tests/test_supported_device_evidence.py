import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "evidence", ROOT / "scripts/capture-supported-device-evidence.py"
)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def host():
    return {"SPHardwareDataType": [{"chip_type": "Apple M4 Max", "machine_name": "Mac"}]}


def device(simulator=False):
    return {
        "devices": [{
            "hardwareProperties": {
                "marketingName": "iPad Pro 13-inch (M4)",
                "productType": "iPad16,6",
                "reality": "simulated" if simulator else "physical",
                "platform": "iOS",
            },
            "deviceProperties": {"osVersionNumber": "27.0"},
            "connectionProperties": {"transport": "Simulator" if simulator else "USB"},
        }]
    }


class SupportedDeviceEvidenceTests(unittest.TestCase):
    def test_exact_match_and_not_run_without_observations(self):
        receipt = MOD.build_receipt(host(), "ProductVersion: 27.0", device())
        self.assertTrue(receipt["host"]["matched"])
        self.assertTrue(receipt["device"]["matched"])
        self.assertEqual(receipt["availability"], "available")
        self.assertTrue(all(row["status"] == "not_run" for row in receipt["scenarios"]))
        self.assertTrue(all(row["evidence"] == "human_only_required" for row in receipt["scenarios"]))

    def test_simulator_is_rejected_and_presence_never_passes(self):
        receipt = MOD.build_receipt(host(), "ProductVersion: 27.0", device(True))
        self.assertFalse(receipt["device"]["matched"])
        self.assertEqual(receipt["availability"], "human_only_required")
        self.assertTrue(all(row["status"] != "pass" for row in receipt["scenarios"]))

    def test_redaction_and_atomic_cli_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profiler = root / "profiler.json"
            profiler.write_text(json.dumps(host() | {"serial_number": "SERIAL-1234567890123456"}))
            sw = root / "sw"
            sw.write_text("ProductVersion: 27.0\n")
            dev = root / "device.json"
            dev.write_text(json.dumps(device() | {
                "udid": "01234567-89AB-CDEF-0123-456789ABCDEF",
                "ip": "192.168.1.2",
                "name": "Private Device Name",
            }))
            output = root / "receipt.json"
            subprocess.run([
                sys.executable,
                str(ROOT / "scripts/capture-supported-device-evidence.py"),
                "--host-system-profiler", str(profiler),
                "--host-sw-vers", str(sw),
                "--device-json", str(dev),
                "--output", str(output),
            ], check=True)
            text = output.read_text()
            self.assertNotIn("SERIAL", text)
            self.assertNotIn("01234567", text)
            self.assertNotIn("192.168", text)
            self.assertNotIn("Private Device Name", text)
            self.assertTrue(json.loads(text)["schema"].endswith(".v1"))

    def test_template_contains_all_scenarios(self):
        template = json.loads(
            (ROOT / "artifacts/cross-repo/physical-template.json").read_text()
        )
        self.assertEqual(
            {row["id"] for row in template["scenarios"]},
            set(MOD.SCENARIOS),
        )
        self.assertTrue(all(row["status"] == "not_run" for row in template["scenarios"]))


if __name__ == "__main__":
    unittest.main()
