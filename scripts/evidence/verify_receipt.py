#!/usr/bin/env python3
"""Strict PhotonPort receipt envelope v2 verifier primitives."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_BYTES = 1048576
PAYLOAD_TYPE = "application/vnd.photonport.receipt.payload.v2+json"
SCRIPT = "scripts/evidence/verify_receipt.py"
SCHEMA = "artifacts/schemas/receipt-envelope-v2.schema.json"
TRUST_POLICY = {
    "schemaVersion": 2,
    "kind": "photonport.trust-policy.v2",
    "testRoot": {
        "keys": {
            "test-ci-hmac-v1": {"alg": "HMAC-SHA256-TEST", "trustDomain": "test", "roles": ["test"], "keyHex": "746573742d63692d686d61632d7631"},
            "test-agent-hmac-v1": {"alg": "HMAC-SHA256-TEST", "trustDomain": "test", "roles": ["test"], "keyHex": "746573742d6167656e742d686d61632d7631"},
        }
    },
    "productionRoot": {
        "publicKeyVerifier": "deferred",
        "keys": {
            "prod-ci-ed25519-v1": {"alg": "ED25519-DSSE", "trustDomain": "opendisplay-ci", "roles": ["automated-ci"], "publicKeyRef": "deferred:opendisplay-ci/prod-ci-ed25519-v1"},
            "prod-human-ed25519-v1": {"alg": "ED25519-DSSE", "trustDomain": "human-approval", "roles": ["release-engineer", "export-reviewer"], "publicKeyRef": "deferred:human-approval/prod-human-ed25519-v1"},
            "prod-provider-ed25519-v1": {"alg": "ED25519-DSSE", "trustDomain": "external-provider", "roles": ["apple-provider"], "publicKeyRef": "deferred:external-provider/prod-provider-ed25519-v1"},
        },
    },
}
GATE_KINDS = {
    "g004.automated": "photonport.gate.g004-automated.v2",
    "g004.physical": "photonport.gate.g004-physical.v2",
    "g006.provenance": "photonport.gate.g006-provenance.v2",
    "export.review": "photonport.gate.export-review.v2",
    "apple.distribution": "photonport.gate.apple-distribution.v2",
    "rollback.build": "photonport.gate.rollback-build.v2",
}
ACTIVE_STATUSES = {"passed", "blocked", "not_run"}
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
RECEIPT_ID_RE = re.compile(r"^r-[A-Za-z0-9._:-]{8,128}$")
ATTEMPT_ID_RE = re.compile(r"^attempt-[A-Za-z0-9._:-]{8,128}$")
REL_PATH_RE = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$)).+")
ISSUER_MATRIX = {
    "g004.automated": {("agent", "test", "test"), ("ci", "automated-ci", "opendisplay-ci")},
    "g004.physical": {("human", "release-engineer", "human-approval")},
    "g006.provenance": {("agent", "test", "test"), ("ci", "automated-ci", "opendisplay-ci")},
    "export.review": {("human", "export-reviewer", "human-approval")},
    "apple.distribution": {("provider", "apple-provider", "external-provider")},
    "rollback.build": {("ci", "automated-ci", "opendisplay-ci")},
}
GATE_STATUSES = {
    "g004.automated": {"passed", "failed", "blocked", "not_run"},
    "g004.physical": {"passed", "failed", "blocked", "not_run"},
    "g006.provenance": {"failed", "blocked", "not_run"},
    "export.review": {"passed", "failed", "blocked", "not_run"},
    "apple.distribution": {"passed", "failed", "blocked", "not_run"},
    "rollback.build": {"passed", "failed", "blocked", "not_run"},
}
PHYSICAL_NONPASSING_ISSUERS = {("agent", "test", "test"), ("ci", "automated-ci", "opendisplay-ci"), ("human", "release-engineer", "human-approval")}


class ReceiptError(Exception):
    def __init__(self, code: str, reason: str):
        super().__init__(reason)
        self.code = code
        self.reason = reason


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ReceiptError("duplicate_json_key", f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _under_root(path: Path, roots: list[Path]) -> bool:
    resolved = path.resolve(strict=False)
    for root in roots:
        try:
            resolved.relative_to(root.resolve(strict=True))
            return True
        except ValueError:
            continue
    return False

def _matching_allowed_root(path: Path, roots: list[Path]) -> Path | None:
    resolved = path.resolve(strict=False)
    for root in roots:
        root_resolved = root.resolve(strict=True)
        try:
            resolved.relative_to(root_resolved)
            return root.absolute()
        except ValueError:
            continue
    return None


def _has_symlink_below_root(path: Path, root: Path) -> bool:
    try:
        relative = path.absolute().relative_to(root.absolute())
    except ValueError:
        return False
    current = root
    for part in relative.parts:
        current = current / part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return False
    return False


def load_json_strict(path: Path, *, max_bytes: int = MAX_BYTES, allowed_roots: list[Path], allow_symlink: bool = False) -> object:
    if not allowed_roots:
        raise ReceiptError("configuration_error", "at least one allowed root is required")
    matching_root = _matching_allowed_root(path, allowed_roots)
    if matching_root is None:
        raise ReceiptError("path_traversal", "input path is outside allowed roots")
    if not allow_symlink and _has_symlink_below_root(path, matching_root):
        raise ReceiptError("symlink_input", "symlink input is not allowed")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ReceiptError("bad_json", str(exc)) from exc
    if len(data) > max_bytes:
        raise ReceiptError("oversized_input", "input exceeds maximum size")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReceiptError("malformed_utf8", "input is not valid UTF-8") from exc
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicates)
    except ReceiptError:
        raise
    except json.JSONDecodeError as exc:
        raise ReceiptError("bad_json", "input is not valid JSON") from exc


def _no_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ReceiptError("payload_not_canonical", "floats are not allowed in canonical JSON")
    if isinstance(value, dict):
        for item in value.values():
            _no_floats(item)
    elif isinstance(value, list):
        for item in value:
            _no_floats(item)


def canonical_json(value: object) -> bytes:
    _no_floats(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(pt)).encode() + b" " + pt + b" " + str(len(payload)).encode() + b" " + payload


def _b64_decode(value: Any, code: str) -> bytes:
    if not isinstance(value, str) or any(c.isspace() for c in value) or "-" in value or "_" in value or len(value) % 4:
        raise ReceiptError(code, "base64 must be standard RFC 4648 with padding and no whitespace")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ReceiptError(code, "invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ReceiptError(code, "base64 is not canonical")
    return decoded


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _expect_obj(value: Any, code: str = "top_level_not_object") -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReceiptError(code, "top-level JSON value must be an object")
    return value


def _require_keys(obj: dict[str, Any], required: set[str], *, code: str = "unknown_receipt_kind") -> None:
    keys = set(obj)
    if keys != required:
        missing = sorted(required - keys)
        extra = sorted(keys - required)
        detail = f"missing keys {missing}" if missing else f"unexpected keys {extra}"
        raise ReceiptError(code, detail)


def _require_obj(value: Any, required: set[str], *, code: str = "unknown_receipt_kind") -> dict[str, Any]:
    obj = _expect_obj(value, code)
    _require_keys(obj, required, code=code)
    return obj


def _require_str(value: Any, *, pattern: re.Pattern[str] | None = None, nonempty: bool = False, code: str = "unknown_receipt_kind") -> str:
    if not isinstance(value, str) or (nonempty and value == "") or (pattern and not pattern.match(value)):
        raise ReceiptError(code, "schema string constraint failed")
    return value


def _require_int(value: Any, *, minimum: int | None = None, code: str = "unknown_receipt_kind") -> int:
    if not isinstance(value, int) or isinstance(value, bool) or (minimum is not None and value < minimum):
        raise ReceiptError(code, "schema integer constraint failed")
    return value


def _parse_utc(value: Any, *, nullable: bool = False, code: str = "unknown_receipt_kind") -> datetime | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ReceiptError(code, "date-time must be UTC with Z suffix")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReceiptError(code, "invalid date-time") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ReceiptError(code, "date-time must be UTC")
    return parsed


def _validate_artifact(value: Any) -> None:
    obj = _require_obj(value, {"path", "sha256", "size"})
    _require_str(obj["path"], pattern=REL_PATH_RE)
    _require_str(obj["sha256"], pattern=HEX64_RE)
    _require_int(obj["size"], minimum=0)


def _validate_child(value: Any) -> None:
    obj = _require_obj(value, {"receiptId", "payloadSha256", "envelopeSha256", "gateId"})
    _require_str(obj["receiptId"], pattern=RECEIPT_ID_RE)
    _require_str(obj["payloadSha256"], pattern=HEX64_RE)
    _require_str(obj["envelopeSha256"], pattern=HEX64_RE)
    if obj["gateId"] not in GATE_KINDS:
        raise ReceiptError("wrong_gate_id", "child gateId is unknown")


def _validate_signature_schema(value: Any) -> dict[str, Any]:
    sig = _require_obj(value, {"keyid", "sig", "alg"}, code="invalid_signature")
    if sig["keyid"] not in {"test-ci-hmac-v1", "test-agent-hmac-v1", "prod-ci-ed25519-v1", "prod-human-ed25519-v1", "prod-provider-ed25519-v1"}:
        raise ReceiptError("unknown_keyid", "unknown signature keyid")
    if sig["alg"] not in {"HMAC-SHA256-TEST", "ED25519-DSSE"}:
        raise ReceiptError("wrong_alg_for_key", "unknown signature alg")
    _b64_decode(sig["sig"], "invalid_signature")
    return sig


def _validate_envelope_schema(envelope: dict[str, Any]) -> None:
    _require_keys(envelope, {"schemaVersion", "kind", "payloadType", "payload", "signatures"}, code="unknown_envelope_kind")
    if envelope["schemaVersion"] != 2:
        raise ReceiptError("unknown_schema_version", "unsupported envelope schemaVersion")
    if envelope["kind"] != "photonport.receipt-envelope.v2":
        raise ReceiptError("unknown_envelope_kind", "unsupported envelope kind")
    if envelope["payloadType"] != PAYLOAD_TYPE:
        raise ReceiptError("bad_payload_type", "unsupported payload type")
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) == 0:
        raise ReceiptError("unsigned_envelope", "receipt envelope must contain exactly one signature")
    if len(signatures) != 1:
        raise ReceiptError("invalid_signature", "receipt envelope must contain exactly one signature")
    _validate_signature_schema(signatures[0])


def _load_policy(path: Path, allowed_roots: list[Path]) -> dict[str, Any]:
    if path.exists():
        policy = _expect_obj(load_json_strict(path, allowed_roots=allowed_roots))
    else:
        policy = TRUST_POLICY
    if policy.get("schemaVersion") != 2 or policy.get("kind") != "photonport.trust-policy.v2":
        raise ReceiptError("configuration_error", "unsupported trust policy")
    test_keys = set(policy.get("testRoot", {}).get("keys", {}))
    prod_keys = set(policy.get("productionRoot", {}).get("keys", {}))
    if test_keys & prod_keys:
        raise ReceiptError("configuration_error", "trust policy key IDs must be disjoint")
    return policy


def _decode_envelope(path: Path, allowed_roots: list[Path]) -> tuple[dict[str, Any], dict[str, Any], bytes, str, str]:
    envelope = _expect_obj(load_json_strict(path, allowed_roots=allowed_roots))
    _validate_envelope_schema(envelope)
    payload_bytes = _b64_decode(envelope.get("payload"), "bad_payload_base64")
    try:
        payload = json.loads(payload_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except UnicodeDecodeError as exc:
        raise ReceiptError("malformed_utf8", "payload is not valid UTF-8") from exc
    except ReceiptError:
        raise
    except json.JSONDecodeError as exc:
        raise ReceiptError("bad_json", "payload is not valid JSON") from exc
    if payload_bytes != canonical_json(payload):
        raise ReceiptError("payload_not_canonical", "payload bytes are not canonical JSON")
    raw = path.read_bytes()
    return envelope, _expect_obj(payload), payload_bytes, _sha(payload_bytes), _sha(raw)


def _validate_payload_schema(payload: dict[str, Any]) -> None:
    allowed = {"schemaVersion", "kind", "receiptId", "releaseAttemptId", "gateId", "status", "sourceTuple", "issuer", "verifier", "invocation", "artifacts", "children", "observationTime"}
    optional = {"expiry", "deviceOs"}
    keys = set(payload)
    missing = allowed - keys
    extra = keys - allowed - optional
    if missing or extra:
        if missing == {"releaseAttemptId"} and not extra:
            raise ReceiptError("missing_release_attempt_id", "releaseAttemptId is required")
        detail = f"missing keys {sorted(missing)}" if missing else f"unexpected keys {sorted(extra)}"
        raise ReceiptError("unknown_receipt_kind", detail)
    if payload["schemaVersion"] != 2:
        raise ReceiptError("unknown_schema_version", "unsupported payload schemaVersion")
    _require_str(payload["receiptId"], pattern=RECEIPT_ID_RE)
    _require_str(payload["releaseAttemptId"], pattern=ATTEMPT_ID_RE, code="missing_release_attempt_id")
    if payload["status"] not in {"passed", "failed", "blocked", "not_run"}:
        raise ReceiptError("gate_not_passed", "unsupported payload status")
    source_tuple = _require_obj(payload["sourceTuple"], {"macCommit", "macTree", "iosCommit", "iosTree", "protocolCommit", "protocolTree", "protocolManifestSha256", "protocolPinSha256"})
    for field in ("macCommit", "macTree", "iosCommit", "iosTree", "protocolCommit", "protocolTree"):
        _require_str(source_tuple[field], pattern=HEX40_RE)
    for field in ("protocolManifestSha256", "protocolPinSha256"):
        _require_str(source_tuple[field], pattern=HEX64_RE)
    issuer = _require_obj(payload["issuer"], {"kind", "identity", "role", "trustDomain"}, code="wrong_role")
    if issuer["kind"] not in {"agent", "ci", "human", "provider"}:
        raise ReceiptError("wrong_role", "unsupported issuer kind")
    _require_str(issuer["identity"], nonempty=True, code="wrong_role")
    if issuer["role"] not in {"test", "automated-ci", "release-engineer", "export-reviewer", "apple-provider"}:
        raise ReceiptError("wrong_role", "unsupported issuer role")
    if issuer["trustDomain"] not in {"test", "opendisplay-ci", "human-approval", "external-provider"}:
        raise ReceiptError("wrong_trust_domain", "unsupported trust domain")
    verifier = _require_obj(payload["verifier"], {"commit", "scriptSha256", "schemaSha256", "trustPolicySha256"})
    _require_str(verifier["commit"], pattern=HEX40_RE)
    for field in ("scriptSha256", "schemaSha256", "trustPolicySha256"):
        _require_str(verifier[field], pattern=HEX64_RE)
    invocation = _require_obj(payload["invocation"], {"tool", "argv", "cwd", "toolchain"})
    _require_str(invocation["tool"], nonempty=True)
    _require_str(invocation["cwd"], nonempty=True)
    if not isinstance(invocation["argv"], list) or not all(isinstance(item, str) for item in invocation["argv"]):
        raise ReceiptError("unknown_receipt_kind", "argv must be an array of strings")
    toolchain = _expect_obj(invocation["toolchain"], "unknown_receipt_kind")
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in toolchain.items()):
        raise ReceiptError("unknown_receipt_kind", "toolchain must contain string values")
    artifacts = _require_obj(payload["artifacts"], {"inputs", "outputs"})
    for key in ("inputs", "outputs"):
        if not isinstance(artifacts[key], list):
            raise ReceiptError("unknown_receipt_kind", "artifact collections must be arrays")
        for item in artifacts[key]:
            _validate_artifact(item)
    if not isinstance(payload["children"], list):
        raise ReceiptError("unknown_receipt_kind", "children must be an array")
    for child in payload["children"]:
        _validate_child(child)
    _parse_utc(payload["observationTime"])
    if "expiry" in payload:
        _parse_utc(payload["expiry"], nullable=True)
    if "deviceOs" in payload:
        device_os = _expect_obj(payload["deviceOs"], "unknown_receipt_kind")
        if set(device_os) - {"host", "device", "transport"}:
            raise ReceiptError("unknown_receipt_kind", "unexpected deviceOs key")
        if not all(isinstance(v, str) for v in device_os.values()):
            raise ReceiptError("unknown_receipt_kind", "deviceOs values must be strings")


def _validate_payload(payload: dict[str, Any], expected: dict[str, Any], *, target: bool) -> None:
    _validate_payload_schema(payload)
    gate = payload.get("gateId")
    kind = payload.get("kind")
    if gate not in GATE_KINDS:
        raise ReceiptError("wrong_gate_id", "unknown gateId")
    if kind not in set(GATE_KINDS.values()):
        raise ReceiptError("unknown_receipt_kind", "unknown receipt kind")
    if kind != GATE_KINDS[gate]:
        raise ReceiptError("wrong_gate_kind", "payload kind does not match gateId")
    if payload["status"] not in GATE_STATUSES[gate]:
        raise ReceiptError("gate_not_passed", "payload status is not permitted for gate")
    if target and expected.get("gateId") and gate != expected["gateId"]:
        raise ReceiptError("wrong_gate_id", "payload gateId does not match expected gate")
    if target and expected.get("kind") and kind != expected["kind"]:
        raise ReceiptError("wrong_gate_kind", "payload kind does not match expected kind")
    if not payload.get("releaseAttemptId"):
        raise ReceiptError("missing_release_attempt_id", "releaseAttemptId is required")
    if expected.get("releaseAttemptId") and payload.get("releaseAttemptId") != expected["releaseAttemptId"]:
        raise ReceiptError("old_release_attempt", "payload release attempt does not match expected attempt")
    if expected.get("sourceTuple") and payload.get("sourceTuple") != expected["sourceTuple"]:
        raise ReceiptError("old_source_tuple", "payload source tuple does not match expected tuple")
    issuer = payload["issuer"]
    allowed_issuers = PHYSICAL_NONPASSING_ISSUERS if gate == "g004.physical" and payload["status"] != "passed" else ISSUER_MATRIX[gate]
    if (issuer["kind"], issuer["role"], issuer["trustDomain"]) not in allowed_issuers:
        matching_kind_role = [entry for entry in allowed_issuers if entry[0] == issuer["kind"] and entry[1] == issuer["role"]]
        if matching_kind_role and all(entry[2] != issuer["trustDomain"] for entry in matching_kind_role):
            raise ReceiptError("wrong_trust_domain", "issuer trust domain is not permitted for gate")
        raise ReceiptError("wrong_role", "issuer kind/role is not permitted for gate")
    verifier = payload.get("verifier", {})
    exp_verifier = expected.get("verifier")
    if not isinstance(exp_verifier, dict):
        raise ReceiptError("configuration_error", "expected verifier digests are required")
    for field, code in (("scriptSha256", "stale_verifier_digest"), ("schemaSha256", "stale_schema_digest"), ("trustPolicySha256", "stale_trust_policy_digest")):
        if field not in exp_verifier:
            raise ReceiptError("configuration_error", f"expected verifier {field} is required")
        if verifier.get(field) != exp_verifier[field]:
            raise ReceiptError(code, f"payload verifier {field} is stale")


def _verify_signature(envelope: dict[str, Any], payload: dict[str, Any], payload_bytes: bytes, policy: dict[str, Any], trust_mode: str) -> tuple[bool, str | None]:
    sig = _expect_obj(envelope["signatures"][0], "invalid_signature")
    keyid = sig.get("keyid")
    alg = sig.get("alg")
    sig_bytes = _b64_decode(sig.get("sig"), "invalid_signature")
    test_keys = policy["testRoot"]["keys"]
    prod_keys = policy["productionRoot"]["keys"]
    if keyid in test_keys:
        key = test_keys[keyid]
        if alg != key.get("alg"):
            raise ReceiptError("wrong_alg_for_key", "signature alg does not match key")
        if trust_mode == "production":
            raise ReceiptError("test_key_in_production", "test keys are not valid in production mode")
        issuer = _expect_obj(payload.get("issuer"), "wrong_role")
        if issuer.get("role") not in key.get("roles", []):
            raise ReceiptError("wrong_role", "issuer role is not trusted by key")
        if issuer.get("trustDomain") != key.get("trustDomain"):
            raise ReceiptError("wrong_trust_domain", "issuer trust domain is not trusted by key")
        expected = hmac.new(bytes.fromhex(key["keyHex"]), dsse_pae(envelope["payloadType"], payload_bytes), hashlib.sha256).digest()
        if not hmac.compare_digest(sig_bytes, expected):
            raise ReceiptError("invalid_signature", "signature does not verify")
        return True, None
    if keyid in prod_keys:
        key = prod_keys[keyid]
        if alg != key.get("alg"):
            raise ReceiptError("wrong_alg_for_key", "signature alg does not match key")
        issuer = _expect_obj(payload.get("issuer"), "wrong_role")
        if issuer.get("role") not in key.get("roles", []):
            raise ReceiptError("wrong_role", "issuer role is not trusted by key")
        if issuer.get("trustDomain") != key.get("trustDomain"):
            raise ReceiptError("wrong_trust_domain", "issuer trust domain is not trusted by key")
        return False, "production_signature_verifier_unavailable"
    raise ReceiptError("unknown_keyid", "unknown signature keyid")


def _active(payload: dict[str, Any], now: datetime) -> bool:
    if payload.get("status") not in ACTIVE_STATUSES:
        return False
    expiry = payload.get("expiry")
    if not expiry:
        return True
    try:
        exp = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
    except ValueError:
        return True
    return exp > now


def _result(path: Path, trust_mode: str, exit_code: int, reason_code: str, reason: str, *, payload: dict[str, Any] | None = None, payload_sha: str | None = None, envelope_sha: str | None = None, trusted: bool = False, checked: list[str] | None = None, verifier: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "kind": "photonport.receipt-verification-result.v2",
        "receiptPath": str(path),
        "receiptId": payload.get("receiptId") if payload else None,
        "releaseAttemptId": payload.get("releaseAttemptId") if payload else None,
        "gateId": payload.get("gateId") if payload else None,
        "payloadKind": payload.get("kind") if payload else None,
        "status": payload.get("status") if payload else "malformed",
        "trusted": trusted,
        "trustMode": trust_mode,
        "exitCode": exit_code,
        "reasonCode": reason_code,
        "reason": reason,
        "payloadSha256": payload_sha,
        "envelopeSha256": envelope_sha,
        "children": payload.get("children", []) if payload else [],
        "checkedReceiptSet": checked or [],
        "verifier": {"scriptSha256": verifier.get("scriptSha256") if verifier else None, "schemaSha256": verifier.get("schemaSha256") if verifier else None, "trustPolicySha256": verifier.get("trustPolicySha256") if verifier else None},
        "observedAt": _now(),
    }


def verify_envelope(receipt_path: Path, *, expected: dict, trust_policy_path: Path, trust_mode: str, receipt_set_paths: list[Path] = [], allowed_roots: list[Path]) -> dict:
    checked: list[str] = []
    payloads: list[tuple[Path, dict[str, Any], dict[str, Any], bytes, str, str]] = []
    expected_verifier = expected.get("verifier") if isinstance(expected.get("verifier"), dict) else None
    try:
        roots = allowed_roots
        policy = _load_policy(trust_policy_path, roots)
        seen_paths: set[Path] = set()
        for path in [receipt_path, *receipt_set_paths]:
            matching_root = _matching_allowed_root(path, roots)
            if matching_root is None:
                raise ReceiptError("path_traversal", "input path is outside allowed roots")
            if _has_symlink_below_root(path, matching_root):
                raise ReceiptError("symlink_input", "symlink input is not allowed")
            resolved = path.resolve(strict=True)
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            checked.append(str(resolved))
            envelope, payload, payload_bytes, payload_sha, envelope_sha = _decode_envelope(resolved, roots)
            _validate_payload(payload, expected, target=not payloads)
            payloads.append((resolved, envelope, payload, payload_bytes, payload_sha, envelope_sha))
        target_envelope = payloads[0][1]
        target_payload = payloads[0][2]
        target_payload_bytes = payloads[0][3]
        target_payload_sha = payloads[0][4]
        target_envelope_sha = payloads[0][5]
        ids: set[str] = set()
        active_gates: set[str] = set()
        by_id: dict[str, tuple[str, str, str]] = {}
        now = datetime.now(timezone.utc)
        for path, envelope, payload, payload_bytes, payload_sha, envelope_sha in payloads:
            rid = payload.get("receiptId")
            if not isinstance(rid, str):
                raise ReceiptError("unknown_receipt_kind", "receiptId is required")
            if rid in ids:
                raise ReceiptError("duplicate_receipt_id", "duplicate receiptId in effective set")
            ids.add(rid)
            by_id[rid] = (payload.get("gateId"), payload_sha, envelope_sha)
            if _active(payload, now):
                gate = payload.get("gateId")
                if gate in active_gates:
                    raise ReceiptError("two_active_receipts_for_gate", "two active receipts for one gate")
                active_gates.add(gate)
        for child in target_payload.get("children", []):
            cid = child.get("receiptId")
            if cid not in by_id or by_id[cid] != (child.get("gateId"), child.get("payloadSha256"), child.get("envelopeSha256")):
                raise ReceiptError("child_hash_mismatch", "child receipt hash mismatch")
        trusted, blocked_code = _verify_signature(target_envelope, target_payload, target_payload_bytes, policy, trust_mode)
        if blocked_code:
            return _result(receipt_path, trust_mode, 2, blocked_code, "production signature verification is deferred in M1", payload=target_payload, payload_sha=target_payload_sha, envelope_sha=target_envelope_sha, trusted=False, checked=checked, verifier=expected_verifier)
        status = target_payload.get("status")
        if status == "passed":
            return _result(receipt_path, trust_mode, 0, "passed", "receipt is trusted and passed", payload=target_payload, payload_sha=target_payload_sha, envelope_sha=target_envelope_sha, trusted=trusted, checked=checked, verifier=expected_verifier)
        if status in {"failed", "blocked", "not_run"}:
            return _result(receipt_path, trust_mode, 2, f"payload_status_{status}", f"receipt payload status is {status}", payload=target_payload, payload_sha=target_payload_sha, envelope_sha=target_envelope_sha, trusted=trusted, checked=checked, verifier=expected_verifier)
        raise ReceiptError("gate_not_passed", "unsupported payload status")
    except ReceiptError as exc:
        return _result(receipt_path, trust_mode, 3, exc.code, exc.reason, payload=payloads[0][2] if payloads else None, payload_sha=payloads[0][4] if payloads else None, envelope_sha=payloads[0][5] if payloads else None, checked=checked, verifier=expected_verifier)
    except Exception as exc:
        return _result(receipt_path, trust_mode, 3, "configuration_error", str(exc), checked=checked, verifier=expected_verifier)


def _expected_from_args(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "releaseAttemptId": args.expected_release_attempt_id,
        "gateId": args.expected_gate_id,
        "kind": args.expected_kind,
        "sourceTuple": {
            "macCommit": args.expected_mac_commit,
            "macTree": args.expected_mac_tree,
            "iosCommit": args.expected_ios_commit,
            "iosTree": args.expected_ios_tree,
            "protocolCommit": args.expected_protocol_commit,
            "protocolTree": args.expected_protocol_tree,
            "protocolManifestSha256": args.expected_protocol_manifest_sha256,
            "protocolPinSha256": args.expected_protocol_pin_sha256,
        },
        "verifier": {
            "scriptSha256": args.expected_verifier_script_sha256,
            "schemaSha256": args.expected_verifier_schema_sha256,
            "trustPolicySha256": args.expected_verifier_trust_policy_sha256,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify PhotonPort receipt envelope v2")
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--trust-policy", required=True, type=Path)
    parser.add_argument("--trust-mode", required=True, choices=["test", "production"])
    parser.add_argument("--expected-release-attempt-id", required=True)
    parser.add_argument("--expected-gate-id", required=True)
    parser.add_argument("--expected-kind", required=True)
    parser.add_argument("--expected-mac-commit", required=True)
    parser.add_argument("--expected-mac-tree", required=True)
    parser.add_argument("--expected-ios-commit", required=True)
    parser.add_argument("--expected-ios-tree", required=True)
    parser.add_argument("--expected-protocol-commit", required=True)
    parser.add_argument("--expected-protocol-tree", required=True)
    parser.add_argument("--expected-protocol-manifest-sha256", required=True)
    parser.add_argument("--expected-protocol-pin-sha256", required=True)
    parser.add_argument("--expected-verifier-script-sha256", required=True)
    parser.add_argument("--expected-verifier-schema-sha256", required=True)
    parser.add_argument("--expected-verifier-trust-policy-sha256", required=True)
    parser.add_argument("--allowed-root", action="append", required=True, type=Path)
    parser.add_argument("--receipt-set", action="append", default=[], type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    result = verify_envelope(
        args.receipt,
        expected=_expected_from_args(args),
        trust_policy_path=args.trust_policy,
        trust_mode=args.trust_mode,
        receipt_set_paths=args.receipt_set,
        allowed_roots=args.allowed_root,
    )
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_json(result) + b"\n")
    except OSError as exc:
        result = _result(args.receipt, args.trust_mode, 3, "output_write_failed", str(exc), verifier=_expected_from_args(args).get("verifier"))
        sys.stderr.write(json.dumps(result, sort_keys=True) + "\n")
        return 3
    return int(result["exitCode"])


if __name__ == "__main__":
    raise SystemExit(main())
