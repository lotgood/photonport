#!/usr/bin/env python3
"""Deterministic, fail-closed retirement readiness verifier for the iOS transition."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

MAX_INPUT_BYTES = 1048576
SCRIPT_PATH = "scripts/verify-ios-transition-readiness.py"
SCHEMA_PATH = "artifacts/schemas/transition-input-v2.schema.json"
DEFAULT_TRUST_POLICY = Path("scripts/evidence/trust-policy.json")

GATES = {
    "g004_automated": ("g004.automated", "g004", "photonport.gate.g004-automated.v2"),
    "g004_physical": ("g004.physical", "g004", "photonport.gate.g004-physical.v2"),
    "g006_provenance": ("g006.provenance", "g006", "photonport.gate.g006-provenance.v2"),
    "export_review": ("export.review", "export_review", "photonport.gate.export-review.v2"),
    "apple_distribution": ("apple.distribution", "apple_distribution", "photonport.gate.apple-distribution.v2"),
    "rollback_build": ("rollback.build", "rollback", "photonport.gate.rollback-build.v2"),
}
KNOWN_KINDS = {kind for _, _, kind in GATES.values()} | {"photonport.transition-input.v2", "photonport.receipt-envelope.v2"}

REASONS = {
    "passed": "typed receipt is trusted and passed",
    "legacy_untrusted_v1": "legacy v1 evidence is historical and cannot establish M0 eligibility",
    "missing_gate_evidence": "gate evidence is absent",
    "gate_not_passed": "legacy gate evidence is not passed and cannot establish M0 eligibility",
    "missing_release_attempt_id": "typed receipt evaluation requires a release attempt id",
    "missing_schema_kind": "receipt is missing schemaVersion and kind",
    "top_level_not_object": "receipt top level must be a JSON object",
    "unknown_schema_version": "receipt schemaVersion is not supported",
    "unknown_receipt_kind": "receipt kind is not supported",
    "unknown_envelope_kind": "receipt envelope kind is not supported",
    "wrong_gate_kind": "receipt kind does not match the supplied gate",
    "bad_json": "receipt is not valid JSON",
    "duplicate_json_key": "receipt contains a duplicate JSON key",
    "malformed_utf8": "receipt is not valid UTF-8",
    "path_traversal": "receipt path is outside allowed roots",
    "symlink_input": "receipt path is a symlink",
    "oversized_input": "receipt exceeds the 1 MiB input limit",
    "typed_receipt_unverified": "typed v2 receipt cannot establish eligibility without trusted verification",
    "old_source_tuple": "receipt source tuple does not match the current three-repo tuple",
    "old_release_attempt": "receipt release attempt id does not match the expected attempt",
    "production_signature_verifier_unavailable": "production signature verification is deferred in M1",
    "repo_state_drift": "repository commit or tree changed during receipt validation",
    "dirty_worktree": "repository worktree is dirty",
    "history_not_preserved": "GPL iOS target/source must remain in the current tree and HEAD history",
    "standalone_missing": "standalone LICENSE/NOTICE/provenance/project and protocol manifest files are required",
    "configuration_error": "required verifier configuration is missing or invalid",
    "output_write_failed": "failed to write transition readiness output atomically",
    "stale_verifier_digest": "receipt verifier script digest is stale",
    "stale_schema_digest": "receipt schema contract digest is stale",
    "stale_trust_policy_digest": "receipt trust policy digest is stale",
}

verify_receipt_api = None


class InputError(Exception):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


def duplicate_rejecting_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate_json_key")
        result[key] = value
    return result


def under_root(path: Path, roots: List[Path]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def reject_symlink_components(path: Path, allowed_root: Path) -> None:
    try:
        relative = path.relative_to(allowed_root)
    except ValueError:
        return
    cursor = allowed_root
    for part in relative.parts:
        cursor = cursor / part
        try:
            if cursor.is_symlink():
                raise InputError("symlink_input")
        except OSError as exc:
            raise InputError("configuration_error") from exc


def lexical_root_for(path: Path, allowed_roots: List[Path]) -> Optional[Path]:
    absolute = path if path.is_absolute() else path.absolute()
    for root in allowed_roots:
        try:
            absolute.relative_to(root)
            return root
        except ValueError:
            continue
    return None


def resolved_root_for(path: Path, allowed_roots: List[Path]) -> Optional[Path]:
    for root in allowed_roots:
        resolved_root = root.resolve(strict=False)
        if path == resolved_root or resolved_root in path.parents:
            return root
    return None


def load_json_strict(path: Path, allowed_roots: List[Path]) -> Any:
    absolute = path if path.is_absolute() else path.absolute()
    declared_root = lexical_root_for(absolute, allowed_roots)
    if declared_root is not None:
        reject_symlink_components(absolute, declared_root)
    if path.is_symlink():
        raise InputError("symlink_input")
    resolved = path.resolve(strict=False)
    if resolved_root_for(resolved, allowed_roots) is None:
        raise InputError("path_traversal")
    try:
        data = resolved.read_bytes()
    except FileNotFoundError:
        raise
    except OSError:
        raise InputError("configuration_error")
    if len(data) > MAX_INPUT_BYTES:
        raise InputError("oversized_input")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError("malformed_utf8")
    try:
        return json.loads(text, object_pairs_hook=duplicate_rejecting_pairs)
    except InputError:
        raise
    except json.JSONDecodeError:
        raise InputError("bad_json")


def load_template(path: Optional[Path]) -> Dict[str, Any]:
    if not path or not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return {}


def git_has(root: Path, path: str) -> bool:
    try:
        return subprocess.run(["git", "-C", str(root), "cat-file", "-e", f"HEAD:{path}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except OSError:
        return False


def git_text(root: Path, path: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(root), "show", f"HEAD:{path}"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8").stdout
    except OSError:
        return ""


def git_output(root: Path, *args: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(root), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise InputError("configuration_error") from exc


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise InputError("configuration_error") from exc

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_required_bytes(path: Path) -> bytes:
    try:
        if path.is_dir():
            raise InputError("configuration_error")
        return path.read_bytes()
    except OSError as exc:
        raise InputError("configuration_error") from exc


def load_required_json(path: Path) -> Any:
    try:
        return json.loads(read_required_bytes(path).decode("utf-8"), object_pairs_hook=duplicate_rejecting_pairs)
    except UnicodeDecodeError as exc:
        raise InputError("malformed_utf8") from exc
    except InputError:
        raise
    except json.JSONDecodeError as exc:
        raise InputError("bad_json") from exc


def schema_contract_bytes(gate_kind: str) -> bytes:
    gate_schema = {
        "photonport.gate.g004-automated.v2": "gate-g004-automated-v2.schema.json",
        "photonport.gate.g004-physical.v2": "gate-g004-physical-v2.schema.json",
        "photonport.gate.g006-provenance.v2": "gate-g006-provenance-v2.schema.json",
        "photonport.gate.export-review.v2": "gate-export-review-v2.schema.json",
        "photonport.gate.apple-distribution.v2": "gate-apple-distribution-v2.schema.json",
        "photonport.gate.rollback-build.v2": "gate-rollback-build-v2.schema.json",
    }[gate_kind]
    schema_dir = Path(__file__).resolve().parents[1] / "artifacts" / "schemas"
    contract = {
        "receiptEnvelope": load_required_json(schema_dir / "receipt-envelope-v2.schema.json"),
        "receiptPayload": load_required_json(schema_dir / "receipt-payload-v2.schema.json"),
        "gate": load_required_json(schema_dir / gate_schema),
    }
    return canonical_json(contract)


def verifier_digests(gate_kind: str, trust_policy_path: Path) -> Dict[str, str]:
    script_path = Path(__file__).resolve().parent / "evidence" / "verify_receipt.py"
    trust_policy_bytes = read_required_bytes(trust_policy_path)
    load_required_json(trust_policy_path)
    return {
        "scriptSha256": sha256_bytes(read_required_bytes(script_path)),
        "schemaSha256": sha256_bytes(schema_contract_bytes(gate_kind)),
        "trustPolicySha256": sha256_bytes(trust_policy_bytes),
    }


def snapshot_root(root: Path) -> Dict[str, str]:
    status = git_output(root, "status", "--porcelain")
    if status:
        raise InputError("dirty_worktree")
    compat = root / "COMPATIBILITY.json"
    if not compat.is_file():
        raise InputError("configuration_error")
    return {"commit": git_output(root, "rev-parse", "HEAD"), "tree": git_output(root, "rev-parse", "HEAD^{tree}"), "compat": sha256_file(compat)}


def snapshot_roots(roots: Dict[str, Path]) -> Dict[str, Dict[str, str]]:
    return {name: snapshot_root(root) for name, root in roots.items()}


def source_tuple_from_snapshot(roots: Dict[str, Path], snap: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    pin = hashlib.sha256(canonical_json({"ios": snap["iosRoot"]["compat"], "mac": snap["macRoot"]["compat"], "protocol": snap["protocolRoot"]["compat"]})).hexdigest()
    return {
        "macRoot": str(roots["macRoot"]), "iosRoot": str(roots["iosRoot"]), "protocolRoot": str(roots["protocolRoot"]),
        "macCommit": snap["macRoot"]["commit"], "macTree": snap["macRoot"]["tree"],
        "iosCommit": snap["iosRoot"]["commit"], "iosTree": snap["iosRoot"]["tree"],
        "protocolCommit": snap["protocolRoot"]["commit"], "protocolTree": snap["protocolRoot"]["tree"],
        "protocolManifestSha256": snap["protocolRoot"]["compat"], "protocolPinSha256": pin,
    }


def current_preserved(mac: Path) -> Dict[str, bool]:
    project = mac / "project.yml"
    target = project.is_file() and "OpenSidecariOS:" in project.read_text(encoding="utf-8", errors="replace")
    source = (mac / "iOS").is_dir() and any((mac / "iOS").rglob("*.swift"))
    return {"target": bool(target), "source": bool(source)}


def history_preserved(mac: Path) -> Dict[str, bool]:
    return {"target": "OpenSidecariOS:" in git_text(mac, "project.yml"), "source": git_has(mac, "iOS/PhoneReceiver.swift")}


def standalone_ready(ios: Path, protocol: Path, template: Dict[str, Any]) -> bool:
    paths = template.get("standalone", {}) if isinstance(template, dict) else {}
    ios_paths = paths.get("ios", ["LICENSE", "NOTICE.md", "PROVENANCE.yml", "project.yml"])
    protocol_paths = paths.get("protocol", ["LICENSE", "COMPATIBILITY.json"])
    return all((ios / str(p)).is_file() for p in ios_paths) and all((protocol / str(p)).is_file() for p in protocol_paths)


def is_legacy_current_structure(value: Dict[str, Any], gate_id: str) -> bool:
    if value.get("schemaVersion") == 1:
        return True
    if gate_id == "g004.automated" and isinstance(value.get("commands"), list):
        return True
    if gate_id == "g004.physical" and ("availability" in value or isinstance(value.get("scenarios"), list)):
        return True
    return False


def legacy_nonpass(value: Dict[str, Any]) -> bool:
    statuses: List[str] = []
    for key in ("status", "result", "availability"):
        if key in value:
            statuses.append(str(value[key]).lower())
    for scenario in value.get("scenarios", []) if isinstance(value.get("scenarios"), list) else []:
        if isinstance(scenario, dict) and "status" in scenario:
            statuses.append(str(scenario["status"]).lower())
    return any(s in {"failed", "blocked", "not_run", "fail", "failed"} for s in statuses)


def load_verify_receipt_api():
    global verify_receipt_api
    if verify_receipt_api is not None:
        return verify_receipt_api
    path = Path(__file__).resolve().parent / "evidence" / "verify_receipt.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("verify_receipt", path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    verify_receipt_api = module
    return module


def reason_text(code: str) -> str:
    return REASONS.get(code, code.replace("_", " "))


def typed_gate_result(gate_id: str, category: str, expected_kind: str, path: Path, args: argparse.Namespace, expected: Dict[str, Any], allowed_roots: List[Path]) -> Dict[str, Any]:
    base = {"gateId": gate_id, "category": category, "inputPath": str(path)}
    if not args.release_attempt_id:
        return {**base, "status": "blocked", "reasonCode": "missing_release_attempt_id", "reason": REASONS["missing_release_attempt_id"]}
    api = load_verify_receipt_api()
    if api is None or not hasattr(api, "verify_envelope"):
        return {**base, "status": "blocked", "reasonCode": "typed_receipt_unverified", "reason": REASONS["typed_receipt_unverified"]}
    verify_expected = dict(expected)
    try:
        verify_expected.update({"releaseAttemptId": args.release_attempt_id, "gateId": gate_id, "kind": expected_kind, "verifier": verifier_digests(expected_kind, args.trust_policy)})
        verdict = api.verify_envelope(path, expected=verify_expected, trust_policy_path=args.trust_policy, trust_mode=args.trust_mode, receipt_set_paths=list(args.receipt_set or []), allowed_roots=allowed_roots)
    except InputError as exc:
        verdict = {"status": "malformed", "exitCode": 3, "reasonCode": exc.reason_code, "reason": reason_text(exc.reason_code), "trusted": False}
    except Exception as exc:
        verdict = {"status": "malformed", "exitCode": 3, "reasonCode": "configuration_error", "reason": str(exc), "trusted": False}
    code = str(verdict.get("reasonCode") or "configuration_error")
    status = str(verdict.get("status") or "malformed")
    exit_code = int(verdict.get("exitCode", 3))
    gate_status = "passed" if exit_code == 0 and verdict.get("trusted") is True and status == "passed" else "blocked" if exit_code == 2 else "malformed"
    return {**base, "status": gate_status, "reasonCode": code, "reason": str(verdict.get("reason") or reason_text(code)), "trusted": bool(verdict.get("trusted")), "verdict": verdict}


def gate_result(gate_id: str, category: str, expected_kind: str, path: Optional[Path], allowed_roots: List[Path], args: argparse.Namespace, expected: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    base = {"gateId": gate_id, "category": category, "inputPath": str(path) if path else None}
    if not path:
        return {**base, "status": "blocked", "reasonCode": "missing_gate_evidence", "reason": REASONS["missing_gate_evidence"]}
    if not path.exists() and not path.is_symlink():
        return {**base, "status": "blocked", "reasonCode": "missing_gate_evidence", "reason": REASONS["missing_gate_evidence"]}
    try:
        value = load_json_strict(path, allowed_roots)
    except InputError as exc:
        return {**base, "status": "malformed", "reasonCode": exc.reason_code, "reason": reason_text(exc.reason_code)}
    except FileNotFoundError:
        return {**base, "status": "blocked", "reasonCode": "missing_gate_evidence", "reason": REASONS["missing_gate_evidence"]}
    if not isinstance(value, dict):
        return {**base, "status": "malformed", "reasonCode": "top_level_not_object", "reason": REASONS["top_level_not_object"]}
    if is_legacy_current_structure(value, gate_id):
        code = "gate_not_passed" if legacy_nonpass(value) else "legacy_untrusted_v1"
        return {**base, "status": "blocked", "reasonCode": code, "reason": REASONS[code]}
    if "schemaVersion" not in value and "kind" not in value:
        return {**base, "status": "malformed", "reasonCode": "missing_schema_kind", "reason": REASONS["missing_schema_kind"]}
    schema = value.get("schemaVersion")
    kind = value.get("kind")
    if schema is not None and schema not in (1, 2):
        return {**base, "status": "malformed", "reasonCode": "unknown_schema_version", "reason": REASONS["unknown_schema_version"]}
    if schema == 2 or kind in KNOWN_KINDS:
        if kind not in KNOWN_KINDS:
            return {**base, "status": "malformed", "reasonCode": "unknown_receipt_kind", "reason": REASONS["unknown_receipt_kind"]}
        if kind == "photonport.receipt-envelope.v2":
            if expected is None:
                if not args.release_attempt_id:
                    return typed_gate_result(gate_id, category, expected_kind, path, args, {}, allowed_roots)
                return {**base, "status": "malformed", "reasonCode": "configuration_error", "reason": REASONS["configuration_error"]}
            return typed_gate_result(gate_id, category, expected_kind, path, args, expected, allowed_roots)
        if kind not in {expected_kind, "photonport.transition-input.v2"}:
            return {**base, "status": "malformed", "reasonCode": "wrong_gate_kind", "reason": REASONS["wrong_gate_kind"]}
        if value.get("gateId") not in (None, gate_id):
            return {**base, "status": "malformed", "reasonCode": "wrong_gate_kind", "reason": REASONS["wrong_gate_kind"]}
        return {**base, "status": "blocked", "reasonCode": "typed_receipt_unverified", "reason": REASONS["typed_receipt_unverified"]}
    if kind is not None and kind not in KNOWN_KINDS:
        return {**base, "status": "malformed", "reasonCode": "unknown_receipt_kind", "reason": REASONS["unknown_receipt_kind"]}
    return {**base, "status": "malformed", "reasonCode": "unknown_receipt_kind", "reason": REASONS["unknown_receipt_kind"]}


def config_gate(reason_code: str, category: str) -> Dict[str, Any]:
    return {"gateId": category, "category": category, "status": "malformed" if reason_code in {"configuration_error", "repo_state_drift", "dirty_worktree"} else "blocked", "reasonCode": reason_code, "reason": reason_text(reason_code), "inputPath": None}


def verify(args: argparse.Namespace) -> Dict[str, Any]:
    trust_mode = getattr(args, "trust_mode", "production")
    input_roots = list(getattr(args, "input_root", []) or [])
    if trust_mode == "production" and input_roots:
        input_root_error = True
        input_roots = []
    else:
        input_root_error = False
    if not hasattr(args, "trust_policy"):
        args.trust_policy = DEFAULT_TRUST_POLICY
    if not hasattr(args, "receipt_set"):
        args.receipt_set = []
    if not hasattr(args, "release_attempt_id"):
        args.release_attempt_id = None
    args.trust_mode = trust_mode

    roots = {"macRoot": Path(args.mac_root).resolve(), "iosRoot": Path(args.ios_root).resolve(), "protocolRoot": Path(args.protocol_root).resolve()}
    gates: List[Dict[str, Any]] = []
    for label, root in roots.items():
        if not root.is_dir():
            gates.append(config_gate("configuration_error", label))
    if input_root_error:
        gates.append(config_gate("configuration_error", "input_root"))
    template = load_template(args.template)
    current = current_preserved(roots["macRoot"]) if roots["macRoot"].is_dir() else {"target": False, "source": False}
    history = history_preserved(roots["macRoot"]) if roots["macRoot"].is_dir() else {"target": False, "source": False}
    standalone = standalone_ready(roots["iosRoot"], roots["protocolRoot"], template) if roots["iosRoot"].is_dir() and roots["protocolRoot"].is_dir() else False
    if not (all(current.values()) and all(history.values())):
        gates.append(config_gate("history_not_preserved", "history"))
    if not standalone:
        gates.append(config_gate("standalone_missing", "standalone"))

    allowed_roots = [Path(getattr(args, name)).absolute() for name in ("mac_root", "ios_root", "protocol_root") if Path(getattr(args, name)).is_dir()] + [Path(root).absolute() for root in input_roots]
    source_tuple = {
        "macRoot": str(roots["macRoot"]), "iosRoot": str(roots["iosRoot"]), "protocolRoot": str(roots["protocolRoot"]),
        "macCommit": None, "macTree": None, "iosCommit": None, "iosTree": None, "protocolCommit": None, "protocolTree": None,
        "protocolManifestSha256": None, "protocolPinSha256": None,
    }
    before = None
    needs_m1_snapshot = bool(input_roots)
    for attr in GATES:
        supplied = getattr(args, attr)
        if supplied and supplied.exists() and not supplied.is_symlink():
            try:
                value = load_json_strict(supplied, allowed_roots)
                needs_m1_snapshot = needs_m1_snapshot or (bool(args.release_attempt_id) and isinstance(value, dict) and value.get("kind") == "photonport.receipt-envelope.v2")
            except (InputError, FileNotFoundError):
                pass
    if needs_m1_snapshot:
        try:
            before = snapshot_roots(roots)
            source_tuple = source_tuple_from_snapshot(roots, before)
        except InputError as exc:
            gates.append(config_gate(exc.reason_code, "sourceTuple"))

    expected_tuple = {k: v for k, v in source_tuple.items() if k not in {"macRoot", "iosRoot", "protocolRoot"}}
    output_verifier = {"script": SCRIPT_PATH, "schema": SCHEMA_PATH}
    for attr, (gate_id, category, kind) in GATES.items():
        gates.append(gate_result(gate_id, category, kind, getattr(args, attr), allowed_roots, args, expected_tuple if before is not None else None))
        if before is not None and getattr(args, attr):
            try:
                digest_set = verifier_digests(kind, args.trust_policy)
                output_verifier.setdefault("receiptVerifier", digest_set)
                output_verifier.update(digest_set)
            except InputError as exc:
                gates.append(config_gate(exc.reason_code, "verifier"))

    if before is not None:
        try:
            after = snapshot_roots(roots)
            if after != before:
                gates.append(config_gate("repo_state_drift", "sourceTuple"))
        except InputError as exc:
            gates.append(config_gate(exc.reason_code, "sourceTuple"))

    retirement_eligible = bool(gates) and all(g.get("status") == "passed" and g.get("trusted") is True and g.get("verdict", {}).get("exitCode") == 0 and g.get("verdict", {}).get("status") == "passed" for g in gates) and all(current.values()) and all(history.values()) and standalone
    exit_code = 3 if any(g["status"] == "malformed" for g in gates) else 0 if retirement_eligible else 2
    blockers = [{"category": g["category"], "reason": g["reason"]} for g in gates if g["status"] != "passed"]
    return {
        "schemaVersion": 2,
        "kind": "ios-transition-readiness-v2",
        "retirementEligible": retirement_eligible,
        "exitCode": exit_code,
        "sourceTuple": source_tuple,
        "preservation": {"currentTree": current, "headHistory": history},
        "standalone": {"present": standalone},
        "gates": gates,
        "blockers": blockers,
        "verifier": output_verifier,
        "observedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }


def write_atomic(path: Path, result: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


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
    ap.add_argument("--trust-policy", type=Path, default=DEFAULT_TRUST_POLICY)
    ap.add_argument("--trust-mode", choices=("test", "production"), default="production")
    ap.add_argument("--release-attempt-id")
    ap.add_argument("--receipt-set", action="append", type=Path, default=[])
    ap.add_argument("--input-root", action="append", type=Path, default=[])
    ap.add_argument("--template", type=Path, default=Path("artifacts/cross-repo/transition-template.json"))
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    result = verify(args)
    try:
        write_atomic(args.output, result)
    except OSError:
        print(REASONS["output_write_failed"], file=os.sys.stderr)
        return 3
    return int(result["exitCode"])


if __name__ == "__main__":
    raise SystemExit(main())
