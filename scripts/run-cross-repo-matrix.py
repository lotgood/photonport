#!/usr/bin/env python3
"""Run and freeze the deterministic G004 automated matrix."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

MAC = Path(__file__).resolve().parents[1]
IOS = Path("/Users/ltg/workspace/photonport-ios")
PROTOCOL = Path("/Users/ltg/workspace/photonport-protocol")
ARTIFACTS = MAC / "artifacts/cross-repo"
LOGS = ARTIFACTS / "logs"
REPORT = ARTIFACTS / "automated-matrix.json"

COMMANDS = [
    (MAC, ["python3", "-m", "unittest", "Tests.test_cross_repo_compatibility", "Tests.test_supported_device_evidence", "Tests.test_mac_protocol_contract", "Tests.test_archive_baselines", "Tests.test_provenance_manifest", "Tests.test_scan_forbidden", "Tests.test_build_inventory", "-v"]),
    (MAC, ["./scripts/test-pairing-vectors.sh"]),
    (MAC, ["./scripts/test-session-binding.sh"]),
    (MAC, ["./scripts/test-mac-protocol-adversarial.sh"]),
    (PROTOCOL, ["python3", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"]),
    (IOS, ["python3", "scripts/run-g003-gates.py"]),
    (IOS, ["python3", "scripts/verify-g003-evidence.py"]),
    (MAC, ["xcodebuild", "-quiet", "-project", "OpenSidecar.xcodeproj", "-scheme", "OpenSidecarMac", "-configuration", "Debug", "-destination", "platform=macOS", "-derivedDataPath", "/tmp/photonport-g004-mac-debug", "CODE_SIGNING_ALLOWED=NO", "build"]),
    (MAC, ["xcodebuild", "-quiet", "-project", "OpenSidecar.xcodeproj", "-scheme", "OpenSidecarMac", "-configuration", "Release", "-destination", "platform=macOS", "-derivedDataPath", "/tmp/photonport-g004-mac-release", "CODE_SIGNING_ALLOWED=NO", "build"]),
    (MAC, ["python3", "scripts/verify-cross-repo-compatibility.py", "--mac-root", str(MAC), "--ios-root", str(IOS), "--protocol-root", str(PROTOCOL), "--output", "artifacts/cross-repo/compatibility-report.json"]),
    (MAC, ["python3", "scripts/capture-supported-device-evidence.py", "--probe-local", "--output", "artifacts/cross-repo/physical-availability.json"]),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def product_identifiers():
    identifiers = []
    for configuration, root in (
        ("Debug", Path("/tmp/photonport-g004-mac-debug")),
        ("Release", Path("/tmp/photonport-g004-mac-release")),
    ):
        candidates = sorted((root / "Build/Products").glob(configuration + "/*.app/Contents/Info.plist"))
        if candidates:
            identifiers.append({
                "configuration": configuration,
                "path": str(candidates[0]),
                "sha256": digest(candidates[0].read_bytes()),
            })
    return identifiers


def main():
    LOGS.mkdir(parents=True, exist_ok=True)
    receipts = []
    result = "passed"
    for index, (cwd, argv) in enumerate(COMMANDS):
        completed = subprocess.run(argv, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        payload = {
            "argv": argv,
            "cwd": str(cwd),
            "exitCode": completed.returncode,
            "stderr": completed.stderr,
            "stdout": completed.stdout,
        }
        log = LOGS / ("%03d.json" % index)
        atomic_json(log, payload)
        receipts.append({
            "argv": argv,
            "cwd": str(cwd),
            "exitCode": completed.returncode,
            "logPath": str(log.relative_to(MAC)),
            "logSha256": digest(log.read_bytes()),
            "stdoutSha256": digest(completed.stdout.encode()),
            "stderrSha256": digest(completed.stderr.encode()),
        })
        if completed.returncode:
            result = "failed"
            break
    compatibility_path = ARTIFACTS / "compatibility-report.json"
    physical_path = ARTIFACTS / "physical-availability.json"
    report = {
        "schemaVersion": 1,
        "kind": "cross-repo-test-report",
        "result": result,
        "commands": receipts,
        "productIdentifiers": product_identifiers(),
        "compatibilityReceipt": {
            "path": str(compatibility_path.relative_to(MAC)),
            "sha256": digest(compatibility_path.read_bytes()) if compatibility_path.is_file() else None,
        },
        "physicalAvailabilityReceipt": {
            "path": str(physical_path.relative_to(MAC)),
            "sha256": digest(physical_path.read_bytes()) if physical_path.is_file() else None,
        },
    }
    atomic_json(REPORT, report)
    return 0 if result == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
