#!/usr/bin/env python3
"""Exercise preservation deletion/rename negatives only in an allocated clone.

This is deliberately not a retirement tool: its only side effect is against the
registered disposable worktree and it emits evidence describing that exercise.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, stat, subprocess, sys
from pathlib import Path

NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = getattr(os, "O_DIRECTORY", 0)
def fail(message): raise RuntimeError(message)
def canon(v): return json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
def digest(v): return hashlib.sha256(canon(v)).hexdigest()
def pairs(items):
    out = {}
    for key, value in items:
        if key in out: fail("duplicate JSON key")
        out[key] = value
    return out
def read_regular(path, label):
    named = path.lstat()
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode): fail(f"{label} must be a regular non-symlink file")
    fd = os.open(path, os.O_RDONLY | NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino): fail(f"{label} changed while opening")
        data = os.read(fd, opened.st_size + 1)
        if len(data) != opened.st_size or os.fstat(fd).st_size != opened.st_size: fail(f"{label} changed while reading")
        return data
    finally: os.close(fd)
def load(path, label):
    try: value = json.loads(read_regular(path, label), object_pairs_hook=pairs)
    except (ValueError, UnicodeDecodeError) as exc: raise RuntimeError(f"invalid {label} JSON") from exc
    if not isinstance(value, dict): fail(f"{label} must be an object")
    return value
def stable_dir(path, label):
    named = path.lstat()
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode): fail(f"{label} must be a non-symlink directory")
    fd = os.open(path, os.O_RDONLY | DIRECTORY | NOFOLLOW)
    opened = os.fstat(fd)
    if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino): os.close(fd); fail(f"{label} changed while opening")
    return fd, opened
def absolute(value, label):
    if not isinstance(value, str) or not Path(value).is_absolute() or Path(os.path.realpath(value)) != Path(value): fail(f"{label} must be canonical absolute")
def root(value, label):
    if not isinstance(value, dict) or set(value) != {"canonicalPath", "dev", "ino"}: fail(f"{label} invalid")
    absolute(value["canonicalPath"], label)
    if not isinstance(value["dev"], int) or not isinstance(value["ino"], int): fail(f"{label} identity invalid")
def member(value):
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value: fail("invalid manifest member")
    parts = value.split("/")
    if any(not p or p in (".", "..") for p in parts): fail("invalid manifest member")
    return parts
def common_git_dir(root_path):
    run = subprocess.run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=root_path, text=True, capture_output=True)
    if run.returncode: fail("registered root is not a Git worktree")
    value = run.stdout.strip(); absolute(value, "common Git directory")
    fd, info = stable_dir(Path(value), "common Git directory")
    os.close(fd)
    return value, info.st_dev, info.st_ino
def checked_child(rootfd, rel):
    fd = os.dup(rootfd)
    try:
        for part in member(rel)[:-1]:
            info = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode): fail("manifest ancestor is unsafe")
            nxt = os.open(part, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=fd); os.close(fd); fd = nxt
        name = member(rel)[-1]
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode): fail("manifest member is a symlink")
        return fd, name, info
    except Exception:
        os.close(fd); raise
def git_value(root_path, expression, label):
    run = subprocess.run(["git", "rev-parse", "--verify", expression], cwd=root_path, text=True, capture_output=True)
    if run.returncode: fail(f"registered root has no {label}")
    value = run.stdout.strip()
    if len(value) != 40 or any(c not in "0123456789abcdef" for c in value): fail(f"registered root {label} is invalid")
    return value
def receipt_module():
    module_path = Path(__file__).with_name("verify_receipt.py")
    spec = importlib.util.spec_from_file_location("r01_receipt_verifier", module_path)
    if spec is None or spec.loader is None: fail("cannot load receipt verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
CANONICAL_KEY_ID = "prod-ci-ed25519-v1"
CANONICAL_ALGORITHM = "ED25519-DSSE"
CANONICAL_TRUST_DOMAIN = "opendisplay-ci"
CANONICAL_ROLE = "automated-ci"
def canonical_trust_policy():
    path = Path(__file__).with_name("trust-policy.json")
    policy = load(path, "canonical trust policy")
    production = policy.get("productionRoot")
    keys = production.get("keys") if isinstance(production, dict) else None
    key = keys.get(CANONICAL_KEY_ID) if isinstance(keys, dict) else None
    if (not isinstance(key, dict) or key.get("alg") != CANONICAL_ALGORITHM
            or key.get("trustDomain") != CANONICAL_TRUST_DOMAIN
            or key.get("roles") != [CANONICAL_ROLE]):
        fail("canonical production trust configuration is invalid")
    return path.resolve()
def attestation(path, label, trust_policy, tuple_value, bindings):
    raw = read_regular(path, label)
    module = receipt_module()
    roots = list({path.parent.resolve(), trust_policy.parent.resolve()})
    try:
        _, payload, _, _, _ = module._decode_envelope(path.resolve(), roots)
    except Exception as exc:
        fail(f"{label} is not a valid DSSE receipt: {exc}")
    expected = {
        "gateId": "g004.automated",
        "kind": "photonport.gate.g004-automated.v2",
        "sourceTuple": payload.get("sourceTuple"),
        "verifier": {
            "scriptSha256": hashlib.sha256(read_regular(Path(module.__file__), "receipt verifier")).hexdigest(),
            "schemaSha256": hashlib.sha256(read_regular(Path(__file__).parents[2] / "artifacts/schemas/receipt-envelope-v2.schema.json", "receipt envelope schema")).hexdigest(),
            "trustPolicySha256": hashlib.sha256(read_regular(trust_policy, "trust policy")).hexdigest(),
            "ed25519ModuleSha256": hashlib.sha256(read_regular(Path(module.__file__).with_name("ed25519_rfc8032.py"), "Ed25519 verifier")).hexdigest(),
        },
    }
    checked = module.verify_envelope(path.resolve(), expected=expected, trust_policy_path=trust_policy, trust_mode="production", allowed_roots=roots)
    if checked.get("exitCode") != 0 or not checked.get("trusted") or checked.get("status") != "passed":
        fail(f"{label} is not a trusted passing receipt: {checked.get('reasonCode')}")
    envelope = load(path, label)
    signatures = envelope.get("signatures")
    if (not isinstance(signatures, list) or len(signatures) != 1
            or signatures[0].get("keyid") != CANONICAL_KEY_ID
            or signatures[0].get("alg") != CANONICAL_ALGORITHM):
        fail(f"{label} must use the canonical production Ed25519 DSSE signature")
    issuer = payload.get("issuer")
    if (not isinstance(issuer, dict) or issuer.get("trustDomain") != CANONICAL_TRUST_DOMAIN
            or issuer.get("role") != CANONICAL_ROLE):
        fail(f"{label} must use the canonical automated CI issuer")
    source = payload.get("sourceTuple")
    if not isinstance(source, dict) or source.get("macCommit") != tuple_value["macCommit"] or source.get("iosCommit") != tuple_value["iosCommit"] or source.get("protocolCommit") != tuple_value["protocolCommit"]:
        fail(f"{label} source tuple does not match clone base tuple")
    for raw_value, binding_label in bindings:
        expected_artifact = {"sha256": hashlib.sha256(raw_value).hexdigest(), "size": len(raw_value)}
        artifacts = payload.get("artifacts", {})
        entries = artifacts.get("inputs", []) + artifacts.get("outputs", []) if isinstance(artifacts, dict) else []
        if not any(isinstance(entry, dict) and entry.get("sha256") == expected_artifact["sha256"] and entry.get("size") == expected_artifact["size"] for entry in entries):
            fail(f"{label} does not bind {binding_label}")
    return {"path": path.name, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}, source
def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--registration", "--allocator-registration", dest="registration", type=Path, required=True)
    p.add_argument("--lifecycle-state", type=Path, required=True)
    p.add_argument("--lifecycle-directory", type=Path, required=True)
    p.add_argument("--manifest", "--closure-manifest", dest="manifest", type=Path, required=True)
    p.add_argument("--inventory", "--target-inventory", dest="inventory", type=Path, required=True)
    p.add_argument("--root", "--clone-root", dest="root", type=Path, required=True)
    p.add_argument("--allocator-attestation", type=Path, required=True)
    p.add_argument("--inventory-attestation", type=Path, required=True)
    p.add_argument("--trust-policy", type=Path,
                   help="deprecated; must name the adjacent canonical trust policy")
    p.add_argument("--trust-mode", choices=("test", "production"),
                   help="deprecated; production is mandatory")
    p.add_argument("--operation", choices=("delete", "rename"), required=True)
    p.add_argument("--result", "--output", dest="result", type=Path, required=True)
    a = p.parse_args()
    trust_policy = canonical_trust_policy()
    if a.trust_policy is not None and Path(os.path.realpath(a.trust_policy)) != trust_policy:
        fail("caller-selected trust policy is not authorized")
    if a.trust_mode not in (None, "production"):
        fail("test trust mode is not authorized for preservation mutations")
    registration_raw = read_regular(a.registration, "allocator registration"); registration = load(a.registration, "allocator registration")
    state_raw = read_regular(a.lifecycle_state, "lifecycle state"); state = load(a.lifecycle_state, "lifecycle state")
    manifest = load(a.manifest, "closure manifest"); inventory_raw = read_regular(a.inventory, "target inventory"); inventory = load(a.inventory, "target inventory")
    lifecycle_fd, lifecycle_info = stable_dir(a.lifecycle_directory, "lifecycle directory")
    try:
        if Path(os.path.realpath(a.lifecycle_state)) != Path(os.path.realpath(a.lifecycle_directory / "010-source-active.json")):
            fail("lifecycle state must be the immutable source-active lifecycle entry")
        allocated_raw = read_regular(a.lifecycle_directory / "000-allocated.json", "allocated lifecycle state")
        allocated = load(a.lifecycle_directory / "000-allocated.json", "allocated lifecycle state")
        # Only an immutable allocator registration can authorize a throwaway clone.
        registration_keys = {"schemaVersion", "kind", "canonicalPath", "dev", "ino", "registrationId", "purpose", "lifecycleId", "commonDir", "authoritativeInventory", "authoritativeInventorySha256"}
        if (set(registration) != registration_keys or registration.get("schemaVersion") != 1
                or registration.get("kind") != "disposable-worktree-registration"):
            fail("registration is not an allocator-issued disposable-worktree registration")
        root({"canonicalPath": registration["canonicalPath"], "dev": registration["dev"], "ino": registration["ino"]}, "registration root")
        absolute(registration["commonDir"], "registration common directory")
        if (not isinstance(registration["registrationId"], str) or not registration["registrationId"]
                or not isinstance(registration["purpose"], str) or not registration["purpose"]
                or not isinstance(registration["lifecycleId"], str) or not registration["lifecycleId"]
                or not isinstance(registration["authoritativeInventorySha256"], str)
                or len(registration["authoritativeInventorySha256"]) != 64
                or any(c not in "0123456789abcdef" for c in registration["authoritativeInventorySha256"])
                or not isinstance(registration["authoritativeInventory"], dict)
                or set(registration["authoritativeInventory"]) != {"members"}
                or not isinstance(registration["authoritativeInventory"]["members"], list)
                or digest(registration["authoritativeInventory"]) != registration["authoritativeInventorySha256"]):
            fail("allocator registration fields are invalid")
        required_state = {"schemaVersion","kind","lifecycleId","rootId","tuple","allocation","authority","state","predecessorSha256","allocationReleaseSha256"}
        if (set(allocated) != required_state - {"allocationReleaseSha256"} or allocated.get("schemaVersion") != 1
                or allocated.get("kind") != "photonport.lifecycle-state.v1" or allocated.get("state") != "allocated"
                or allocated.get("predecessorSha256") is not None):
            fail("immutable allocated lifecycle state required")
        if set(state) != required_state or state.get("schemaVersion") != 1 or state.get("kind") != "photonport.lifecycle-state.v1" or state.get("state") != "source-active": fail("immutable source-active lifecycle state required")
        if (state.get("predecessorSha256") != hashlib.sha256(allocated_raw).hexdigest()
                or any(state.get(key) != allocated.get(key) for key in ("lifecycleId", "rootId", "tuple", "allocation", "authority"))):
            fail("lifecycle allocation chain is not immutable")
        if registration["lifecycleId"] != state["lifecycleId"]: fail("registration lifecycle differs from source-active lifecycle")
        authority = state["authority"]
        if not isinstance(authority, dict) or set(authority) != {"approvedSequence","root","supervisor","command","allocationNonce","mutexNonce","lockAPath","lockBPath","registryPath","commonGitDir"}: fail("lifecycle authority invalid")
        root(authority["root"], "authority root")
        absolute(authority["registryPath"], "allocator registry")
        absolute(authority["commonGitDir"], "lifecycle common Git directory")
    finally:
        if (os.fstat(lifecycle_fd).st_dev, os.fstat(lifecycle_fd).st_ino) != (lifecycle_info.st_dev, lifecycle_info.st_ino):
            os.close(lifecycle_fd); fail("lifecycle directory changed while reading")
        os.close(lifecycle_fd)
    rootfd, rootinfo = stable_dir(a.root, "mutation root")
    try:
        actual = {"canonicalPath": str(Path(os.path.realpath(a.root))), "dev": rootinfo.st_dev, "ino": rootinfo.st_ino}
        if (actual != authority["root"] or actual != {"canonicalPath": registration["canonicalPath"], "dev": registration["dev"], "ino": registration["ino"]}):
            fail("root is not the registered allocated clone")
        # Issuer and all non-clone evidence must remain outside the clone.
        for path, label in ((a.registration,"registration"),(a.lifecycle_directory,"lifecycle directory"),(a.lifecycle_state,"lifecycle state"),(a.manifest,"manifest"),(a.inventory,"inventory"),(a.allocator_attestation,"allocator attestation"),(a.inventory_attestation,"inventory attestation"),(trust_policy,"canonical trust policy"),(a.result,"result")):
            if os.path.commonpath((str(Path(os.path.realpath(path))), actual["canonicalPath"])) == actual["canonicalPath"]: fail(f"{label} must be outside clone")
        registry_fd, registry_info = stable_dir(Path(authority["registryPath"]), "allocator registry")
        try:
            if Path(os.path.realpath(a.registration.parent)) != Path(authority["registryPath"]):
                fail("registration is not located in the allocator registry")
        finally:
            os.close(registry_fd)
        common, common_dev, common_ino = common_git_dir(a.root)
        if common != authority["commonGitDir"] or common != registration["commonDir"]: fail("common Git directory does not match immutable registration")
        registration_sha256 = hashlib.sha256(registration_raw).hexdigest()
        expected_keys = {"schemaVersion","kind","lifecycleId","rootId","root","commonGitDir","commonGitDirDev","commonGitDirIno","registrationSha256","registrationId","authoritativeInventorySha256","members"}
        if set(inventory) != expected_keys or inventory.get("schemaVersion") != 1 or inventory.get("kind") != "photonport.r01-preservation-target-inventory.v1": fail("authoritative inventory descriptor invalid")
        manifest_keys = expected_keys | {"inventorySha256", "allocatorAttestation", "inventoryAttestation"}
        if set(manifest) != manifest_keys or manifest.get("schemaVersion") != 1 or manifest.get("kind") != "photonport.r01-preservation-closure-manifest.v1": fail("closure manifest invalid")
        for record in (inventory, manifest):
            if (record.get("lifecycleId") != state["lifecycleId"] or record.get("rootId") != state["rootId"]
                    or record.get("root") != actual or record.get("commonGitDir") != common
                    or record.get("commonGitDirDev") != common_dev or record.get("commonGitDirIno") != common_ino
                    or record.get("registrationSha256") != registration_sha256
                    or record.get("registrationId") != registration["registrationId"]
                    or record.get("authoritativeInventorySha256") != registration["authoritativeInventorySha256"]):
                fail("preservation evidence identity mismatch")
        if inventory["members"] != registration["authoritativeInventory"]["members"]:
            fail("inventory is not the allocator-authoritative inventory descriptor")
        if manifest["inventorySha256"] != digest(inventory): fail("manifest is not bound to authoritative inventory")
        targets = inventory.get("members"); claimed = manifest.get("members")
        if not isinstance(targets, list) or not targets or len(set(targets)) != len(targets) or any(member(x) is None for x in targets): fail("inventory members invalid")
        if not isinstance(claimed, list) or len(set(claimed)) != len(claimed) or any(member(x) is None for x in claimed) or set(claimed) != set(targets): fail("manifest members omit or add authoritative targets")
        base_commit = git_value(a.root, "HEAD", "base commit")
        base_tree = git_value(a.root, "HEAD^{tree}", "base tree")
        if base_commit != state["tuple"]["macCommit"]: fail("clone base commit differs from lifecycle tuple")
        bindings = ((registration_raw, "external allocator registration"), (state_raw, "immutable lifecycle state"), (inventory_raw, "authoritative target inventory"))
        allocator_attestation, allocator_source = attestation(a.allocator_attestation, "allocator attestation", trust_policy, state["tuple"], bindings)
        inventory_attestation, inventory_source = attestation(a.inventory_attestation, "inventory attestation", trust_policy, state["tuple"], bindings)
        if allocator_source != inventory_source or allocator_source.get("macTree") != base_tree:
            fail("trusted attestations do not bind the clone base tree")
        if manifest["allocatorAttestation"] != allocator_attestation or manifest["inventoryAttestation"] != inventory_attestation:
            fail("closure manifest attestation bindings differ from trusted attestations")
        for target in sorted(targets, key=lambda x: (x.count('/'), x), reverse=True):
            parent, name, info = checked_child(rootfd, target)
            try:
                if a.operation == "delete":
                    if stat.S_ISDIR(info.st_mode): os.rmdir(name, dir_fd=parent)
                    else: os.unlink(name, dir_fd=parent)
                else: os.rename(name, name + ".r01-preservation-renamed", src_dir_fd=parent, dst_dir_fd=parent)
            finally: os.close(parent)
        result = {"schemaVersion":1,"kind":"photonport.r01-preservation-mutation-result.v1","lifecycleId":state["lifecycleId"],"rootId":state["rootId"],"root":actual,"commonGitDir":common,"commonGitDirDev":common_dev,"commonGitDirIno":common_ino,"registrationSha256":registration_sha256,"registrationId":registration["registrationId"],"authoritativeInventorySha256":registration["authoritativeInventorySha256"],"allocatorAttestation":allocator_attestation,"inventoryAttestation":inventory_attestation,"manifestSha256":digest(manifest),"inventorySha256":digest(inventory),"operation":a.operation,"members":sorted(targets)}
        fd = os.open(a.result, os.O_WRONLY|os.O_CREAT|os.O_EXCL|NOFOLLOW, 0o600)
        try: os.write(fd, canon(result)+b"\n"); os.fsync(fd)
        finally: os.close(fd)
    finally: os.close(rootfd)
if __name__ == "__main__":
    try: main()
    except Exception as exc: print(f"run-r01-preservation-mutations.py: error: {exc}", file=sys.stderr); sys.exit(2)
