#!/usr/bin/env python3
"""Capture a redacted, read-only receipt for the single supported device matrix."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SUPPORTED_HOST = {"model": "Apple M4 Max", "os_major": "27"}
SUPPORTED_DEVICE = {"model": "iPad Pro 11-inch (M4)", "os_major": "27", "platform": "iOS"}
SUPPORTED_DEVICE_NORMALIZED_MODEL = "ipad pro 11-inch (m4)"
SCENARIOS = [
    "usb_display", "usb_hdr", "usb_120hz", "usb_audio", "usb_rotation",
    "usb_input", "usb_disconnect", "usb_replug", "wifi_sas", "wifi_tls",
    "wifi_unpaired", "wifi_wrong_mac", "wifi_takeover", "wifi_reconnect",
]
SENSITIVE_KEY = re.compile(r"(serial|udid|identifier|device.?id|ip|address|token|secret|seed|psk|proof|sas)", re.I)
SENSITIVE_VALUE = re.compile(r"(?i)(?:[0-9a-f]{16,}|(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{8}-[0-9a-f-]{27,})")


def _redact(value: Any, key: str = "") -> Any:
    if SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v, key) for v in value]
    if isinstance(value, str) and SENSITIVE_VALUE.search(value):
        return SENSITIVE_VALUE.sub("[REDACTED]", value)
    return value


def _read(path: Optional[str]) -> str:
    if not path:
        return ""
    return Path(path).read_text(encoding="utf-8")


def _json_or_text(text: str) -> Any:
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return text


def _major(version: str) -> str:
    match = re.search(r"\b(\d+)(?:\.\d+)?", version or "")
    return match.group(1) if match else ""


def _find_values(obj: Any, names: Iterable[str]) -> List[str]:
    wanted = {n.lower() for n in names}
    found: List[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key.lower() in wanted and isinstance(value, (str, int, float)):
                found.append(str(value))
            found.extend(_find_values(value, wanted))
    elif isinstance(obj, list):
        for value in obj:
            found.extend(_find_values(value, wanted))
    return found


def host_identity(profiler: Any, swvers: str) -> Dict[str, Any]:
    models = _find_values(profiler, ("machine_name", "model_name", "model", "computer_name", "chip_type", "cpu_type", "processor_name"))
    model = next((m for m in models if "m4" in m.lower()), models[0] if models else "")
    if not model and isinstance(profiler, str):
        match = re.search(r"Apple\s+M4\s+Max", profiler, re.I)
        model = match.group(0) if match else ""
    version = next((v for v in _find_values(_json_or_text(swvers), ("productversion", "product_version", "osversion", "version")) if _major(v)), swvers)
    if isinstance(_json_or_text(swvers), str):
        version = swvers
    return {"model": model, "os_major": _major(version), "matched": model.lower() == SUPPORTED_HOST["model"].lower() and _major(version) == SUPPORTED_HOST["os_major"]}


def _devices(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("devices", "deviceList", "results"):
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]
        for value in data.values():
            result = _devices(value)
            if result:
                return result
    return []


def _normalized_model(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().lower()


def device_identity(data: Any) -> Dict[str, Any]:
    devices = _devices(data)
    if not devices:
        return {"model": "", "normalized_model": "", "os_major": "", "platform": "", "transport": "", "physical": False, "matched": False, "reason": "no_device"}

    candidates = []
    for device in devices:
        values = _find_values(device, ("marketingName", "modelName", "productType", "hardwareModel"))
        model = next((value for value in values if _normalized_model(value) == SUPPORTED_DEVICE_NORMALIZED_MODEL), values[0] if values else "")
        normalized_model = _normalized_model(model)
        model_matches = normalized_model == SUPPORTED_DEVICE_NORMALIZED_MODEL
        versions = _find_values(device, ("osVersionNumber", "osVersion", "os_version", "productVersion", "version"))
        platform = next(iter(_find_values(device, ("platform", "platformType", "devicePlatform"))), "")
        transport = next(iter(_find_values(device, ("transport", "connectionType", "connection"))), "")
        realities = _find_values(device, ("reality",))
        serialized = json.dumps(device).lower()
        simulated = any(value.lower() == "simulated" for value in realities) or "simulator" in serialized
        physical = not simulated and (
            any(value.lower() == "physical" for value in realities)
            or any(marker in serialized for marker in ("usb", "physical", "wired"))
        )
        os_major = _major(versions[0] if versions else "")
        matched = (
            model_matches
            and os_major == SUPPORTED_DEVICE["os_major"]
            and platform.lower() in ("ios", "iphoneos")
            and physical
        )
        reason = (
            f"matched:{normalized_model}"
            if matched
            else f"{'simulator_rejected' if simulated else 'missing_or_unsupported_physical_device'}:{normalized_model}"
        )
        identity = {
            "model": model,
            "normalized_model": normalized_model,
            "os_major": os_major,
            "platform": platform,
            "transport": transport,
            "physical": physical,
            "matched": matched,
            "reason": reason,
        }
        rank = (
            int(model_matches),
            int(physical),
            int(platform.lower() in ("ios", "iphoneos")),
        )
        candidates.append((rank, identity))
    return max(candidates, key=lambda item: item[0])[1]


def _probe() -> Tuple[str, str, str]:
    with tempfile.NamedTemporaryFile(prefix="devicectl-", suffix=".json", delete=False) as handle:
        output = handle.name
    try:
        host = subprocess.run(["system_profiler", "SPHardwareDataType", "-json"], check=True, capture_output=True, text=True).stdout
        sw = subprocess.run(["sw_vers"], check=True, capture_output=True, text=True).stdout
        subprocess.run(["xcrun", "devicectl", "list", "devices", "--json-output", output], check=True, capture_output=True, text=True)
        return host, sw, Path(output).read_text(encoding="utf-8")
    finally:
        try: os.unlink(output)
        except OSError: pass


def build_receipt(profiler: Any, swvers: str, devices: Any, observations: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    host, device = host_identity(profiler, swvers), device_identity(devices)
    supplied = observations or {}
    rows = []
    for name in SCENARIOS:
        observation = supplied.get(name, {})
        if not isinstance(observation, dict):
            observation = {}
        status = observation.get("status", "not_run")
        if status == "pass" and not (host["matched"] and device["matched"]):
            status = "not_run"
        rows.append({"id": name, "status": status, "evidence": observation.get("evidence", "human_only_required")})
    return {"schema": "opendisplay.supported-device-evidence.v1", "supported_matrix": {"host": SUPPORTED_HOST, "device": SUPPORTED_DEVICE}, "host": host, "device": device, "availability": "available" if host["matched"] and device["matched"] else "human_only_required", "scenarios": rows}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-system-profiler", "--system-profiler", dest="host_system_profiler")
    parser.add_argument("--host-sw-vers", "--sw-vers", dest="host_sw_vers")
    parser.add_argument("--device-json", "--devicectl", "--device-list", dest="device_json")
    parser.add_argument("--observations")
    parser.add_argument("--output", required=True)
    parser.add_argument("--probe-local", action="store_true")
    args = parser.parse_args(argv)
    if args.probe_local:
        profiler_text, sw_text, device_text = _probe()
    else:
        if not (args.host_system_profiler and args.host_sw_vers and args.device_json):
            parser.error("fixture mode requires --host-system-profiler, --host-sw-vers, and --device-json")
        profiler_text, sw_text, device_text = _read(args.host_system_profiler), _read(args.host_sw_vers), _read(args.device_json)
    observations = _json_or_text(_read(args.observations)) if args.observations else {}
    receipt = _redact(build_receipt(_json_or_text(profiler_text), sw_text, _json_or_text(device_text), observations if isinstance(observations, dict) else {}))
    payload = json.dumps(receipt, sort_keys=True, indent=2) + "\n"
    destination = Path(args.output); destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=destination.name + ".", dir=str(destination.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream: stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        try: os.unlink(temporary)
        except OSError: pass
    return 0

if __name__ == "__main__":
    sys.exit(main())
