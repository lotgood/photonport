#!/usr/bin/env python3
"""Run and freeze the deterministic M3 cross-repo production interop matrix."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

VERIFIER = Path(__file__).resolve().with_name("verify-cross-repo-compatibility.py")
EXPECTED_PIN_KEYS = {"schemaVersion", "protocolCommit", "compatibilityDigest", "normativeManifestDigest"}
NEGATIVE_FRAME = b"\x00\x00\x00\x00"
VECTOR_RECEIPT_PREFIX = "VECTOR_RECEIPT "


def digest(data):
    return hashlib.sha256(data).hexdigest()
def canonical_mutation(mutation):
    if not isinstance(mutation, dict) or set(mutation) != {"dimension", "value"}:
        raise ValueError("mutation must contain exactly dimension and value")
    if not isinstance(mutation["dimension"], str) or not mutation["dimension"]:
        raise ValueError("mutation dimension must be a nonempty string")
    try:
        encoded = json.dumps(mutation, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("mutation is not canonical JSON") from exc
    return encoded, digest(encoded)



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


def require_dir(path, label):
    resolved = Path(path).resolve()
    if not resolved.is_dir():
        raise SystemExit(label + " root is not a directory: " + str(path))
    return resolved


def require_full_hex(value, label, length):
    if len(value) != length or any(c not in "0123456789abcdef" for c in value):
        raise SystemExit(label + " must be " + str(length) + " lowercase hex characters")
    return value


def require_source_binding(root, expected_commit, label):
    def git_query(argv):
        completed = subprocess.run(["git", "-C", str(root), *argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if completed.returncode:
            raise SystemExit("FAIL_CLOSED: " + label + " source binding query failed: git " + " ".join(argv))
        return completed.stdout.decode("utf-8", "replace").strip()

    head = git_query(["rev-parse", "HEAD"])
    if head != expected_commit:
        raise SystemExit(
            "FAIL_CLOSED: " + label + " checkout HEAD " + head + " does not match expected commit " + expected_commit
            + "; matrix evidence binds only the executed snapshot, so post-hoc re-pinning is refused and an"
            + " evidence-recording commit (one storing receipts/tooling/docs) can never be claimed as executed"
        )
    if git_query(["status", "--porcelain"]):
        raise SystemExit(
            "FAIL_CLOSED: " + label + " checkout is not a clean snapshot of " + expected_commit
            + "; matrix evidence must bind an immutable clean source tree"
        )


def run(argv, cwd, log_dir, label, *, stdin=None):
    completed = subprocess.run(argv, cwd=cwd, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    log_path = log_dir / (label + ".json")
    payload = {
        "label": label,
        "argv": [str(part) for part in argv],
        "exitCode": completed.returncode,
        "stderr": completed.stderr.decode("utf-8", "replace"),
        "stdoutSha256": digest(completed.stdout),
        "stdoutBytes": len(completed.stdout),
    }
    atomic_json(log_path, payload)
    return completed, {
        "label": label,
        "exitCode": completed.returncode,
        "logPath": "logs/" + log_path.name,
    }


def consumer_vector_receipts(stdout, platform, cases):
    """Parse exact, metadata-bound consumer rejection receipts from one suite."""
    try:
        lines = stdout.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        raise ValueError("consumer suite output is not valid UTF-8")
    expected = {case["id"]: case for case in cases if case["ownership"]["consumerPlatform"] == platform}
    receipts = {}
    for line in lines:
        if not line.startswith(VECTOR_RECEIPT_PREFIX):
            continue
        fields = line.split(" ")
        if len(fields) != 7 or fields[0:2] != ["VECTOR_RECEIPT", "consumer"]:
            raise ValueError("malformed consumer receipt: " + line)
        case_id, mutation, mutation_sha256, stage, outcome = fields[2:]
        if (
            not mutation.startswith("mutation=")
            or not mutation_sha256.startswith("mutationSha256=")
            or not stage.startswith("stage=")
            or not outcome.startswith("outcome=")
        ):
            raise ValueError("malformed consumer receipt: " + line)
        if case_id in receipts:
            raise ValueError("duplicate consumer receipt ID: " + case_id)
        case = expected.get(case_id)
        if case is None:
            raise ValueError("consumer receipt is not owned by " + platform + ": " + case_id)
        try:
            _, expected_digest = canonical_mutation(case["mutation"])
        except (KeyError, ValueError) as exc:
            raise ValueError("consumer receipt mutation metadata is invalid: " + case_id) from exc
        if mutation.removeprefix("mutation=") != case["mutation"]["dimension"]:
            raise ValueError("consumer receipt mutation does not match metadata: " + case_id)
        if mutation_sha256.removeprefix("mutationSha256=") != expected_digest:
            raise ValueError("consumer receipt mutation digest does not match metadata: " + case_id)
        if stage.removeprefix("stage=") != case["ownership"]["stage"]:
            raise ValueError("consumer receipt stage does not match metadata: " + case_id)
        if outcome != "outcome=rejected":
            raise ValueError("consumer receipt outcome is not rejected: " + case_id)
        receipts[case_id] = {
            "id": case_id,
            "ownership": case["ownership"],
            "mutation": case["mutation"],
            "mutationSha256": expected_digest,
        }
    return receipts


def empty_vector_evidence():
    return {
        "positive": {"producer": {}, "consumer": {}},
        "negative": {"producer": {}, "consumer": {}},
    }


def evidence_ids(evidence, kind, role, case_ids):
    return [case_id for case_id in case_ids if evidence[kind][role].get(case_id)]


def record_suite_vector_evidence(evidence, consumer_platform, passed, stdout, negative_cases):
    if not passed or consumer_platform is None:
        return None
    receipts = consumer_vector_receipts(stdout, consumer_platform, negative_cases)
    evidence["negative"]["consumer"].update({case_id: True for case_id in receipts})
    return receipts


def covered_negative_vector_ids(negative_cases, evidence):
    return evidence_ids(evidence, "negative", "consumer", [case["id"] for case in negative_cases])

def read_pin_bytes(data, path):
    def pairs_hook(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key " + key)
            value[key] = item
        return value

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs_hook)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"FAIL_CLOSED: malformed build pin {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit("FAIL_CLOSED: build pin must be a JSON object: " + str(path))
    allowed = set(EXPECTED_PIN_KEYS)
    if "protocolTag" in value:
        allowed.add("protocolTag")
        if not isinstance(value["protocolTag"], str):
            raise SystemExit("FAIL_CLOSED: protocolTag must be a string: " + str(path))
    if set(value) != allowed or type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1:
        raise SystemExit("FAIL_CLOSED: build pin fields are not exact: " + str(path))
    for field, length in (
        ("protocolCommit", 40),
        ("compatibilityDigest", 64),
        ("normativeManifestDigest", 64),
    ):
        item = value.get(field)
        if not isinstance(item, str) or len(item) != length or any(c not in "0123456789abcdef" for c in item):
            raise SystemExit(f"FAIL_CLOSED: build pin {field} is not lowercase full hex: {path}")
    return value


def pin_evidence(path):
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"FAIL_CLOSED: malformed build pin {path}: {exc}") from exc
    return read_pin_bytes(data, path), digest(data)


def read_pin(path):
    return pin_evidence(path)[0]



def compile_launchers(mac, ios, build, logs, receipts):
    mac_bin = build / "mac-interop"
    ios_bin = build / "ios-interop"
    commands = [
        (
            mac,
            [
                "swiftc", "-O",
                str(mac / "Tests/MacInteropLauncher.swift"),
                str(mac / "Mac/ProtocolParser.swift"),
                str(mac / "Mac/Pairing.swift"),
                str(mac / "Mac/Log.swift"),
                "-o", str(mac_bin),
            ],
            "compile-mac-launcher",
        ),
        (
            mac,
            [
                "swiftc", "-O",
                str(mac / "Tests/IOSInteropLauncher.swift"),
                str(ios / "Sources/StrictJSON.swift"),
                str(ios / "Sources/ReceiverContracts.swift"),
                str(ios / "Sources/Pairing.swift"),
                str(ios / "Sources/Log.swift"),
                "-o", str(ios_bin),
            ],
            "compile-ios-launcher-host",
        ),
    ]
    for cwd, argv, label in commands:
        completed, receipt = run(argv, cwd, logs, label)
        receipts.append(receipt)
        if completed.returncode:
            return None, None
    return mac_bin, ios_bin


def single_built_pin(products_root, label):
    candidates = sorted(path for path in products_root.rglob("ProtocolBuildPin.json") if ".app" in path.as_posix())
    if len(candidates) != 1:
        raise RuntimeError(f"{label} build produced {len(candidates)} ProtocolBuildPin.json resources")
    return pin_evidence(candidates[0])


def built_pins_match(expected_pin, source_pins, built_pins, source_pin_sha256, built_pin_sha256):
    return (
        source_pins == {"mac": expected_pin, "ios": expected_pin}
        and built_pins == source_pins
        and built_pin_sha256 == source_pin_sha256
    )


def build_product_pins(mac, ios, ios_commit, build, logs, receipts):
    mac_derived = build / "mac-product"
    ios_source = build / "ios-source"
    ios_derived = build / "ios-product"
    commands = [
        (
            mac,
            [
                "xcodebuild", "-quiet", "-project", "OpenSidecar.xcodeproj",
                "-scheme", "OpenSidecarMac", "-configuration", "Debug",
                "-destination", "platform=macOS", "-derivedDataPath", str(mac_derived),
                "CODE_SIGNING_ALLOWED=NO", "build",
            ],
            "build-mac-product",
        ),
    ]
    for cwd, argv, label in commands:
        completed, receipt = run(argv, cwd, logs, label)
        receipts.append(receipt)
        if completed.returncode:
            raise RuntimeError(label + " failed")

    if not git_clone_checkout(ios, ios_source, ios_commit, mac, logs, "build-ios-source", receipts):
        raise RuntimeError("iOS product source clone/checkout failed")
    for cwd, argv, label in (
        (ios_source, ["./generate.sh"], "generate-ios-product-project"),
        (
            ios_source,
            [
                "xcodebuild", "-quiet", "-project", "PhotonPortReceiver.xcodeproj",
                "-scheme", "PhotonPortReceiver", "-configuration", "Debug",
                "-sdk", "iphonesimulator", "-destination", "generic/platform=iOS Simulator",
                "-derivedDataPath", str(ios_derived), "CODE_SIGNING_ALLOWED=NO", "build",
            ],
            "build-ios-product",
        ),
    ):
        completed, receipt = run(argv, cwd, logs, label)
        receipts.append(receipt)
        if completed.returncode:
            raise RuntimeError(label + " failed")

    return (
        single_built_pin(mac_derived / "Build/Products", "Mac"),
        single_built_pin(ios_derived / "Build/Products", "iOS"),
    )


def exchange_once(encoder, vector, decoder, logs, name, receipts):
    encoded, encode_receipt = run([str(encoder), "encode", vector], encoder.parent, logs, name + "-encode")
    receipts.append(encode_receipt)
    if encoded.returncode:
        return False
    decoded, decode_receipt = run([str(decoder), "decode"], decoder.parent, logs, name + "-decode", stdin=encoded.stdout)
    receipts.append(decode_receipt)
    return decoded.returncode == 0


def negative_decode(decoder, logs, name, receipts):
    decoded, receipt = run([str(decoder), "decode"], decoder.parent, logs, name, stdin=NEGATIVE_FRAME)
    receipts.append(receipt)
    return decoded.returncode != 0


def strict_vector_object(path, label):
    def pairs_hook(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key " + key)
            value[key] = item
        return value

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs_hook)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"FAIL_CLOSED: malformed {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"FAIL_CLOSED: {label} must be a JSON object")
    return value


def load_negative_cases(protocol_root):
    schema = strict_vector_object(protocol_root / "schemas/negative-vectors.schema.json", "negative vector schema")
    value = strict_vector_object(protocol_root / "vectors/negative.json", "negative vectors")
    expected_root_fields = set(schema.get("properties", {}))
    if (
        schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
        or set(schema.get("required", [])) != expected_root_fields
        or set(value) != expected_root_fields
        or value.get("protocol") != schema["properties"]["protocol"].get("const")
        or value.get("version") != schema["properties"]["version"].get("const")
        or value.get("expectedOutcome") != schema["properties"]["expectedOutcome"].get("const")
        or not isinstance(value.get("cases"), list)
        or not value["cases"]
        or not isinstance(value.get("invariants"), list)
        or not all(isinstance(item, str) for item in value["invariants"])
        or not isinstance(value.get("strictContractSuites"), dict)
    ):
        raise SystemExit("FAIL_CLOSED: negative vectors do not validate against negative vector schema")
    definitions = schema.get("$defs", {})
    case_schema = definitions.get("case", {})
    ownership_schema = definitions.get("ownership", {})
    mutation_schema = definitions.get("mutation", {})
    optional_case_fields = {"baseline", "encoding"}
    required_case_fields = set(case_schema.get("required", []))
    allowed_case_fields = set(case_schema.get("properties", {}))
    allowed_platforms = set(ownership_schema.get("properties", {}).get("consumerPlatform", {}).get("enum", []))
    allowed_directions = set(ownership_schema.get("properties", {}).get("direction", {}).get("enum", []))
    allowed_stages = set(ownership_schema.get("properties", {}).get("stage", {}).get("enum", []))
    if (
        case_schema.get("additionalProperties") is not False
        or ownership_schema.get("additionalProperties") is not False
        or mutation_schema.get("additionalProperties") is not False
        or not required_case_fields
        or not allowed_platforms
        or not allowed_directions
        or not allowed_stages
    ):
        raise SystemExit("FAIL_CLOSED: negative vector schema is unsupported")
    cases = []
    identifiers = set()
    for case in value["cases"]:
        if not isinstance(case, dict) or not required_case_fields.issubset(case) or not set(case).issubset(allowed_case_fields):
            raise SystemExit("FAIL_CLOSED: negative vector case does not validate against schema")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id or case_id in identifiers:
            raise SystemExit("FAIL_CLOSED: duplicate or invalid negative vector case id")
        if (
            not isinstance(case.get("message"), str)
            or not case["message"]
            or case.get("outcome") != value["expectedOutcome"]
            or any(field in case and not isinstance(case[field], str) for field in optional_case_fields)
        ):
            raise SystemExit("FAIL_CLOSED: negative vector case fields are invalid: " + case_id)
        ownership = case.get("ownership")
        mutation = case.get("mutation")
        if (
            not isinstance(ownership, dict)
            or set(ownership) != set(ownership_schema.get("required", []))
            or ownership.get("consumerPlatform") not in allowed_platforms
            or ownership.get("direction") not in allowed_directions
            or ownership.get("stage") not in allowed_stages
            or not isinstance(mutation, dict)
            or set(mutation) != {"dimension", "value"}
            or not isinstance(mutation.get("dimension"), str)
            or not mutation["dimension"]
        ):
            raise SystemExit("FAIL_CLOSED: negative vector ownership/mutation is invalid: " + case_id)
        identifiers.add(case_id)
        cases.append(case)
    return cases


def load_positive_case_ids(protocol_root):
    session = strict_vector_object(protocol_root / "vectors/session-v3.json", "session vectors")
    pairing = strict_vector_object(protocol_root / "vectors/pairing-v2.json", "pairing vectors")
    cases = session.get("cases")
    frames = session.get("frames")
    if session.get("protocol") != "session-v3" or session.get("version") != "3.0.0" or not isinstance(cases, list) or not isinstance(frames, dict):
        raise SystemExit("FAIL_CLOSED: session vector header/cases/frames are invalid")
    names = [case.get("name") for case in cases if isinstance(case, dict)]
    if len(names) != len(cases) or not names or not all(isinstance(name, str) and name for name in names) or len(names) != len(set(names)):
        raise SystemExit("FAIL_CLOSED: session vector case names are invalid or duplicated")
    if pairing.get("protocol") != "pairing-v2" or pairing.get("version") != "2.0.0" or not isinstance(pairing.get("outputs"), dict):
        raise SystemExit("FAIL_CLOSED: pairing vector header/outputs are invalid")
    identifiers = ["pairing-v2:canonical"]
    identifiers.extend("session-v3:" + name for name in names)
    identifiers.extend("session-v3-frame:" + key for key in sorted(frames) if isinstance(key, str))
    return identifiers






def run_production_suites(mac, ios, protocol, logs, receipts, positive_ids, negative_cases):
    commands = [
        (mac, ["./scripts/test-session-binding.sh"], "suite-mac-session-vectors", None),
        (ios, ["./scripts/test-session-binding.sh"], "suite-ios-session-vectors", None),
        (ios, ["./scripts/test-pairing-vectors.sh"], "suite-ios-pairing-vectors", None),
        (
            protocol,
            [
                sys.executable, "-m", "unittest",
                "tests.test_protocol.ProtocolTests.test_pairing_vector_recomputes_every_output",
                "tests.test_protocol.ProtocolTests.test_session_vectors_recompute_every_output",
                "tests.test_protocol.ProtocolTests.test_usb_binding_vectors_preface_records_and_key_separation",
                "-v",
            ],
            "suite-protocol-positive-vectors",
            None,
        ),
        (
            protocol,
            [
                sys.executable, "-m", "unittest",
                "tests.test_protocol.ProtocolTests.test_every_negative_vector_is_exercised",
                "-v",
            ],
            "suite-protocol-negative-vectors",
            None,
        ),
        (
            protocol,
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
            "suite-protocol-conformance",
            None,
        ),
    ]
    results = {}
    evidence = empty_vector_evidence()
    consumer_receipts = []
    receipt_errors = []
    for cwd, argv, label, consumer_platform in commands:
        completed, receipt = run(argv, cwd, logs, label)
        receipts.append(receipt)
        passed = completed.returncode == 0
        results[label] = passed
        try:
            parsed = record_suite_vector_evidence(
                evidence, consumer_platform, passed, completed.stdout, negative_cases
            )
        except ValueError as exc:
            receipt_errors.append(label + ": " + str(exc))
            continue
        if label == "suite-protocol-negative-vectors" and passed:
            evidence["negative"]["producer"] = {case["id"]: True for case in negative_cases}
        elif label == "suite-protocol-positive-vectors" and passed:
            evidence["positive"]["producer"] = {case_id: True for case_id in positive_ids}
        if parsed is not None:
            consumer_receipts.extend({**item, "commandReceipt": receipt} for item in parsed.values())
    for case in negative_cases:
        platform = case["ownership"]["consumerPlatform"]
        if platform == "mac-client":
            cwd = mac
            mutation_json, mutation_sha256 = canonical_mutation(case["mutation"])
            argv = ["./scripts/test-mac-protocol-adversarial.sh", "case", case["id"],
                    mutation_json.decode("utf-8"), mutation_sha256]
        elif platform == "ios-server":
            cwd = ios
            mutation_json, mutation_sha256 = canonical_mutation(case["mutation"])
            argv = ["./scripts/test-receiver-adversarial.sh", case["id"],
                    mutation_json.decode("utf-8"), mutation_sha256]
        else:
            receipt_errors.append("unsupported consumer platform: " + platform)
            continue
        label = "negative-consumer-" + platform + "-" + case["id"]
        completed, receipt = run(argv, cwd, logs, label)
        receipts.append(receipt)
        if completed.returncode != 0:
            receipt_errors.append(label + ": consumer command failed")
            continue
        try:
            parsed = consumer_vector_receipts(completed.stdout, platform, [case])
        except ValueError as exc:
            receipt_errors.append(label + ": " + str(exc))
            continue
        if set(parsed) != {case["id"]}:
            receipt_errors.append(label + ": exact consumer receipt missing")
            continue
        evidence["negative"]["consumer"][case["id"]] = True
        consumer_receipts.extend({**item, "commandReceipt": receipt} for item in parsed.values())
    return results, evidence, consumer_receipts, receipt_errors


def git_clone_checkout(src, dst, commit, mac, logs, label, receipts):
    completed, receipt = run(["git", "clone", "--no-local", str(src), str(dst)], mac, logs, label + "-clone")
    receipts.append(receipt)
    if completed.returncode:
        return False
    completed, receipt = run(["git", "-C", str(dst), "checkout", "--detach", commit], mac, logs, label + "-checkout")
    receipts.append(receipt)
    return completed.returncode == 0


def verifier_command(mac, ios, protocol, output, args):
    command = [
        sys.executable, str(VERIFIER),
        "--mac-root", str(mac),
        "--ios-root", str(ios),
        "--protocol-root", str(protocol),
        "--mac-pin", "Mac/ProtocolBuildPin.json",
        "--ios-pin", "Resources/ProtocolBuildPin.json",
        "--expected-mac-commit", args.expected_mac_commit,
        "--expected-ios-commit", args.expected_ios_commit,
        "--expected-protocol-commit", args.expected_protocol_commit,
        "--expected-compatibility-digest", args.expected_compatibility_digest,
        "--expected-normative-manifest-digest", args.expected_normative_manifest_digest,
        "--output", str(output),
    ]
    if args.authorize_protocol_tag:
        command.extend(["--authorize-protocol-tag", args.authorize_protocol_tag])
    return command


def semantic_receipt(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    value.pop("snapshots", None)
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mac-root", required=True)
    parser.add_argument("--ios-root", required=True)
    parser.add_argument("--protocol-root", required=True)
    parser.add_argument("--expected-mac-commit", required=True)
    parser.add_argument("--expected-ios-commit", required=True)
    parser.add_argument("--expected-protocol-commit", required=True)
    parser.add_argument("--expected-compatibility-digest", required=True)
    parser.add_argument("--expected-normative-manifest-digest", required=True)
    parser.add_argument("--authorize-protocol-tag")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    mac = require_dir(args.mac_root, "mac")
    ios = require_dir(args.ios_root, "ios")
    protocol = require_dir(args.protocol_root, "protocol")
    require_full_hex(args.expected_mac_commit, "expected mac commit", 40)
    require_full_hex(args.expected_ios_commit, "expected ios commit", 40)
    require_full_hex(args.expected_protocol_commit, "expected protocol commit", 40)
    require_full_hex(args.expected_compatibility_digest, "expected compatibility digest", 64)
    require_full_hex(args.expected_normative_manifest_digest, "expected normative manifest digest", 64)
    require_source_binding(mac, args.expected_mac_commit, "mac")
    require_source_binding(ios, args.expected_ios_commit, "ios")
    require_source_binding(protocol, args.expected_protocol_commit, "protocol")
    authorized_tag_value = None
    if args.authorize_protocol_tag:
        prefix = "refs/tags/"
        if not args.authorize_protocol_tag.startswith(prefix) or len(args.authorize_protocol_tag) == len(prefix):
            raise SystemExit("authorized protocol tag must be a fully qualified refs/tags/... name")
        authorized_tag_value = args.authorize_protocol_tag.removeprefix(prefix)

    report_path = Path(args.output).resolve()
    artifacts = report_path.parent
    logs = artifacts / "logs"
    compatibility_path = artifacts / "compatibility-report.json"
    fresh_path = artifacts / "compatibility-report-fresh.json"
    logs.mkdir(parents=True, exist_ok=True)

    receipts = []
    failures = []
    executed_positive = []
    executed_adversarial = {"mac-client": [], "ios-server": []}
    consumer_negative_receipts = []
    suite_results = {}
    vector_evidence_map = empty_vector_evidence()
    source_pins = {}
    built_pins = {}
    source_pin_sha256 = {}
    built_pin_sha256 = {}
    result = "passed"

    negative_cases = load_negative_cases(protocol)
    negative_ids = [case["id"] for case in negative_cases]
    positive_ids = load_positive_case_ids(protocol)
    suite_results, vector_evidence_map, consumer_negative_receipts, receipt_errors = run_production_suites(
        mac, ios, protocol, logs, receipts, positive_ids, negative_cases
    )
    failures.extend(receipt_errors)
    for receipt in consumer_negative_receipts:
        executed_adversarial[receipt["ownership"]["consumerPlatform"]].append(receipt["id"])
    for label, passed in suite_results.items():
        if not passed:
            failures.append(label + " failed")
    positive_suite_labels = (
        "suite-mac-session-vectors",
        "suite-ios-session-vectors",
        "suite-ios-pairing-vectors",
        "suite-protocol-positive-vectors",
    )
    producer_covered = evidence_ids(vector_evidence_map, "negative", "producer", negative_ids)
    covered = covered_negative_vector_ids(negative_cases, vector_evidence_map)
    unexecutable = [case_id for case_id in negative_ids if case_id not in covered]
    if unexecutable:
        failures.append("protocol negative vector IDs lack exact production consumer receipt coverage")
    if all(suite_results.get(label) for label in positive_suite_labels):
        positive_suite_covered = list(positive_ids)
    with tempfile.TemporaryDirectory(prefix="photonport-m3-matrix-") as tmp:
        build = Path(tmp) / "build"
        build.mkdir()
        expected_pin = {"schemaVersion": 1, "protocolCommit": args.expected_protocol_commit, "compatibilityDigest": args.expected_compatibility_digest, "normativeManifestDigest": args.expected_normative_manifest_digest}
        if authorized_tag_value:
            expected_pin["protocolTag"] = authorized_tag_value
        source_pin_evidence = {
            "mac": pin_evidence(mac / "Mac/ProtocolBuildPin.json"),
            "ios": pin_evidence(ios / "Resources/ProtocolBuildPin.json"),
        }
        source_pins = {label: evidence[0] for label, evidence in source_pin_evidence.items()}
        source_pin_sha256 = {label: evidence[1] for label, evidence in source_pin_evidence.items()}
        try:
            built_mac_evidence, built_ios_evidence = build_product_pins(
                mac, ios, args.expected_ios_commit, build, logs, receipts
            )
            built_pin_evidence = {"mac": built_mac_evidence, "ios": built_ios_evidence}
            built_pins = {label: evidence[0] for label, evidence in built_pin_evidence.items()}
            built_pin_sha256 = {label: evidence[1] for label, evidence in built_pin_evidence.items()}
            if not built_pins_match(
                expected_pin, source_pins, built_pins, source_pin_sha256, built_pin_sha256
            ):
                failures.append("built product pin bytes do not match tracked source pins and expected tuple")
        except RuntimeError as exc:
            failures.append(str(exc))

        mac_bin, ios_bin = compile_launchers(mac, ios, build, logs, receipts)
        if not mac_bin or not ios_bin:
            failures.append("launcher compilation failed")
        else:

            vectors = [
                (mac_bin, "ping", ios_bin, "mac-to-ios-ping"),
                (mac_bin, "touch", ios_bin, "mac-to-ios-touch"),
                (mac_bin, "scroll", ios_bin, "mac-to-ios-scroll"),
                (mac_bin, "keyframe", ios_bin, "mac-to-ios-keyframe"),
                (mac_bin, "session-open", ios_bin, "mac-to-ios-session-open-v3"),
                (ios_bin, "pong", mac_bin, "ios-to-mac-pong"),
                (ios_bin, "stats", mac_bin, "ios-to-mac-stats"),
                (ios_bin, "keyframe", mac_bin, "ios-to-mac-keyframe"),
                (ios_bin, "session-accept", mac_bin, "ios-to-mac-session-accept-v3"),
            ]
            for encoder, vector, decoder, name in vectors:
                if exchange_once(encoder, vector, decoder, logs, name, receipts):
                    executed_positive.append(name)
                else:
                    failures.append(name + " failed")
                    break
            if not negative_decode(mac_bin, logs, "negative-to-mac-zero-length", receipts):
                failures.append("mac decoder accepted invalid zero-length frame")
            if not negative_decode(ios_bin, logs, "negative-to-ios-zero-length", receipts):
                failures.append("ios decoder accepted invalid zero-length frame")
            if len(executed_positive) != len(vectors) or len(positive_suite_covered) != len(positive_ids):
                failures.append("protocol positive vector IDs lack executable production-suite coverage")

        verifier = verifier_command(mac, ios, protocol, compatibility_path, args)
        completed, receipt = run(verifier, mac, logs, "verifier-primary")
        receipts.append(receipt)
        if completed.returncode:
            failures.append("primary verifier failed")

        changed_root = Path(tmp) / "changed-pin-mac"
        if git_clone_checkout(mac, changed_root, args.expected_mac_commit, mac, logs, "changed-pin-mac", receipts):
            changed_pin = changed_root / "Mac/ProtocolBuildPin.json"
            changed_value = read_pin(changed_pin)
            changed_value["compatibilityDigest"] = "0" * 64
            changed_pin.write_text(json.dumps(changed_value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            changed_verifier = verifier_command(changed_root, ios, protocol, Path(tmp) / "changed-pin.json", args)
            completed, receipt = run(changed_verifier, changed_root, logs, "verifier-changed-pin-failure")
            receipts.append(receipt)
            stderr = completed.stderr.decode("utf-8", "replace")
            if completed.returncode == 0 or "FAIL_CLOSED" not in stderr or not ("pin" in stderr.lower() and ("tracked" in stderr.lower() or "mismatch" in stderr.lower())):
                failures.append("changed tracked pin did not fail closed for a pin tracked-change/mismatch reason")
        else:
            failures.append("changed-pin git clone/checkout failed")

        fresh_mac = Path(tmp) / "fresh-mac"
        fresh_ios = Path(tmp) / "fresh-ios"
        fresh_protocol = Path(tmp) / "fresh-protocol"
        fresh_ready = all([
            git_clone_checkout(mac, fresh_mac, args.expected_mac_commit, mac, logs, "fresh-mac", receipts),
            git_clone_checkout(ios, fresh_ios, args.expected_ios_commit, mac, logs, "fresh-ios", receipts),
            git_clone_checkout(protocol, fresh_protocol, args.expected_protocol_commit, mac, logs, "fresh-protocol", receipts),
        ])
        if fresh_ready:
            fresh_verifier = verifier_command(fresh_mac, fresh_ios, fresh_protocol, fresh_path, args)
            completed, receipt = run(fresh_verifier, fresh_mac, logs, "verifier-fresh-path")
            receipts.append(receipt)
            semantic_equal = completed.returncode == 0 and compatibility_path.is_file() and fresh_path.is_file() and semantic_receipt(compatibility_path) == semantic_receipt(fresh_path)
            if not semantic_equal:
                failures.append("fresh clone semantic equality failed")
        else:
            failures.append("fresh git clone/checkout failed")

    if failures:
        result = "failed"
    report = {
        "schemaVersion": 2,
        "kind": "cross-repo-production-interop-report",
        "result": result,
        "sourceTuple": {
            "macCommit": args.expected_mac_commit,
            "iosCommit": args.expected_ios_commit,
            "protocolCommit": args.expected_protocol_commit,
            "compatibilityDigest": args.expected_compatibility_digest,
            "normativeManifestDigest": args.expected_normative_manifest_digest,
        },
        "coverageContract": {
            "positiveRawFrameCases": executed_positive,
            "productionDerivedAdversarialCases": executed_adversarial,
            "vectorEvidence": {
                kind: {
                    role: evidence_ids(vector_evidence_map, kind, role, case_ids)
                    for role in ("producer", "consumer")
                }
                for kind, case_ids in (("positive", positive_ids), ("negative", negative_ids))
            },
            "productionConsumerNegativeVectorReceipts": evidence_ids(
                vector_evidence_map, "negative", "consumer", negative_ids
            ),
            "negativeConsumerReceiptMetadata": consumer_negative_receipts,
            "protocolProducerNegativeVectorIDs": producer_covered,
            "enumeratedProtocolPositiveVectorIDs": positive_ids,
            "enumeratedProtocolNegativeVectorIDs": negative_ids,
            "productionSuiteResults": suite_results,
            "productionSuiteCoveredPositiveVectorIDs": positive_suite_covered,
            "productionSuiteCoveredNegativeVectorIDs": covered,
            "negativeVectorEvidenceLabels": ["exact metadata-bound production consumer receipt", "suite-protocol-negative-vectors producer reference"],
            "positiveVectorEvidenceLabels": list(positive_suite_labels),
            "unexecutableNegativeVectorIDs": unexecutable,
            "unexecutablePolicy": "matrix fails closed on missing, duplicate, extra, wrong-platform, wrong-stage, or non-rejected metadata-bound consumer receipts; Protocol suite success supplies producer evidence only",
        },
        "processProtocol": {
            "topology": "separate production-derived Swift executables",
            "framing": "4-byte big-endian length followed by raw payload bytes over stdout/stdin",
            "directions": ["mac-encoder-to-ios-decoder", "ios-encoder-to-mac-decoder"],
            "negativeCases": ["zero-length frame exits nonzero", "metadata-owned adversarial consumer suite emits exactly one rejected receipt per declared case"],
        },
        "builtPinEvidence": {
            "trackedConsumerPins": source_pins,
            "builtProductPins": built_pins,
            "trackedConsumerPinSha256": source_pin_sha256,
            "builtProductPinSha256": built_pin_sha256,
        },
        "commands": receipts,
        "failures": failures,
        "compatibilityReceipt": {"path": str(compatibility_path.relative_to(artifacts)), "sha256": digest(compatibility_path.read_bytes()) if compatibility_path.is_file() else None},
        "freshCompatibilityReceipt": {"path": str(fresh_path.relative_to(artifacts)), "sha256": digest(fresh_path.read_bytes()) if fresh_path.is_file() else None},
        "physicalAvailability": "outside automated matrix evidence DAG; S-P1-05 OPEN-WAIVED",
    }
    atomic_json(report_path, report)
    return 0 if result == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
