#!/usr/bin/env python3
"""Deterministic, fail-closed retirement readiness verifier for the iOS transition."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


BLOCKERS = {
    "history": "preserved GPL iOS target/source history",
    "standalone": "standalone iOS/protocol identities and manifests",
    "g004": "G004 automated and physical evidence",
    "g006": "G006 provenance evidence",
    "export_review": "independent export review",
    "apple_distribution": "Apple credentials/signing/TestFlight/publication evidence",
    "rollback": "rollback build evidence",
}


def load(path: Optional[Path]) -> Any:
    if not path or not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None


def passed(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"pass", "passed", "success", "succeeded", "ready", "complete", "completed"}
    if isinstance(value, dict):
        for key in ("result", "status", "outcome", "approval_status"):
            if key in value and isinstance(value[key], (str, bool)):
                if passed(value[key]):
                    return True
        return bool(value.get("passed") is True or value.get("ready") is True)
    return False


def git_has(root: Path, path: str) -> bool:
    try:
        return subprocess.run(["git", "-C", str(root), "cat-file", "-e", "HEAD:{0}".format(path)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except OSError:
        return False


def git_text(root: Path, path: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(root), "show", "HEAD:{0}".format(path)],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                              encoding="utf-8").stdout
    except OSError:
        return ""


def current_preserved(mac: Path) -> Dict[str, bool]:
    project = mac / "project.yml"
    target = project.is_file() and "OpenSidecariOS:" in project.read_text(encoding="utf-8", errors="replace")
    source = (mac / "iOS").is_dir() and any((mac / "iOS").rglob("*.swift"))
    return {"target": bool(target), "source": bool(source)}


def history_preserved(mac: Path) -> Dict[str, bool]:
    return {"target": "OpenSidecariOS:" in git_text(mac, "project.yml"),
            "source": git_has(mac, "iOS/PhoneReceiver.swift")}


def physical_ready(receipt: Any) -> bool:
    if not isinstance(receipt, dict) or not passed(receipt.get("result", receipt.get("status"))):
        return False
    scenarios = receipt.get("scenarios", receipt.get("physicalScenarios", []))
    if not isinstance(scenarios, list) or not scenarios:
        return False
    required = {"usb", "wifi"}
    seen = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict) or not passed(scenario.get("result", scenario.get("status"))):
            return False
        if str(scenario.get("os_major", scenario.get("osMajor", ""))) != "27":
            return False
        if scenario.get("physical") is not True:
            return False
        transport = str(scenario.get("transport", scenario.get("id", ""))).lower()
        if transport.startswith("usb"):
            seen.add("usb")
        if transport.startswith("wifi"):
            seen.add("wifi")
    return seen == required


def standalone_ready(ios: Path, protocol: Path, template: Dict[str, Any]) -> bool:
    paths = template.get("standalone", {}) if isinstance(template, dict) else {}
    ios_paths = paths.get("ios", ["LICENSE", "NOTICE.md", "PROVENANCE.yml", "project.yml"])
    protocol_paths = paths.get("protocol", ["LICENSE", "COMPATIBILITY.json"])
    return all((ios / str(p)).is_file() for p in ios_paths) and all((protocol / str(p)).is_file() for p in protocol_paths)


def verify(args: argparse.Namespace) -> Dict[str, Any]:
    mac, ios, protocol = map(lambda p: Path(p).resolve(), (args.mac_root, args.ios_root, args.protocol_root))
    template = load(args.template) or {}
    current = current_preserved(mac)
    history = history_preserved(mac)
    blockers: List[Dict[str, str]] = []

    def require(category: str, ok: bool, detail: str) -> None:
        if not ok:
            blockers.append({"category": category, "reason": detail})

    require("history", all(current.values()) and all(history.values()), "GPL iOS target/source must remain in the current tree and HEAD history")
    require("standalone", standalone_ready(ios, protocol, template), "standalone LICENSE/NOTICE/provenance/project and protocol manifest files are required")
    automated = load(args.g004_automated)
    physical = load(args.g004_physical)
    require("g004", passed(automated) and physical_ready(physical), "G004 automated receipt and both physical macOS/iPadOS 27 USB/Wi-Fi scenarios must pass")
    require("g006", passed(load(args.g006_provenance)), "G006 provenance receipt must pass")
    export = load(args.export_review)
    require("export_review", passed(export) and (not isinstance(export, dict) or export.get("independent") is not False), "independent export review must pass")
    apple = load(args.apple_distribution)
    apple_ok = isinstance(apple, dict) and all(apple.get(k) is True for k in ("credentials", "signing", "testflight", "publication")) and passed(apple.get("result", True))
    require("apple_distribution", apple_ok, "Apple credentials, signing, TestFlight, and publication evidence must pass")
    require("rollback", passed(load(args.rollback_build)), "rollback build receipt must pass")
    result = {
        "schemaVersion": 1,
        "retirementReady": not blockers,
        "preservation": {"currentTree": current, "headHistory": history},
        "standalone": {"present": standalone_ready(ios, protocol, template)},
        "blockers": blockers,
    }
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mac-root", required=True, type=Path)
    ap.add_argument("--ios-root", required=True, type=Path)
    ap.add_argument("--protocol-root", required=True, type=Path)
    ap.add_argument("--g004-automated", type=Path, default=Path("artifacts/cross-repo/automated-matrix.json"))
    ap.add_argument("--g004-physical", type=Path, default=Path("artifacts/cross-repo/physical-availability.json"))
    ap.add_argument("--g006-provenance", type=Path)
    ap.add_argument("--export-review", type=Path)
    ap.add_argument("--apple-distribution", type=Path)
    ap.add_argument("--rollback-build", type=Path)
    ap.add_argument("--template", type=Path, default=Path("artifacts/cross-repo/transition-template.json"))
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    result = verify(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=args.output.name + ".", dir=str(args.output.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, args.output)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
