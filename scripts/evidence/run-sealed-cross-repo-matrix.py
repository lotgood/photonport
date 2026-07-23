#!/usr/bin/env python3
"""Seal a known cross-repository matrix run as source-free evidence."""
import argparse, fcntl, hashlib, hmac, json, os, stat, subprocess, sys, tempfile
from pathlib import Path

IDS = ("mac", "ios", "protocol")
HEX64 = set("0123456789abcdef")
PRODUCTION_RUNNER = Path(__file__).resolve().parents[1] / "run-cross-repo-matrix.py"
INNER_FIELDS = {"schemaVersion", "kind", "result", "sourceTuple", "coverageContract", "processProtocol", "builtPinEvidence", "commands", "failures", "compatibilityReceipt", "freshCompatibilityReceipt", "physicalAvailability"}
MUTEX_NAME = "source-root.mutex"
COVERAGE_FIELDS = {"positiveRawFrameCases", "productionDerivedAdversarialCases", "enumeratedProtocolPositiveVectorIDs", "enumeratedProtocolNegativeVectorIDs", "productionSuiteResults", "productionSuiteCoveredPositiveVectorIDs", "productionSuiteCoveredNegativeVectorIDs", "negativeVectorEvidenceLabels", "positiveVectorEvidenceLabels", "unexecutableNegativeVectorIDs", "unexecutablePolicy"}
PIN_FIELDS = {"schemaVersion", "protocolCommit", "compatibilityDigest", "normativeManifestDigest"}
NEGATIVE_LABELS = {"suite-mac-adversarial", "suite-ios-adversarial", "suite-protocol-negative-vectors"}
POSITIVE_LABELS = {"suite-mac-session-vectors", "suite-ios-session-vectors", "suite-ios-pairing-vectors", "suite-protocol-positive-vectors"}
PROCESS = {"topology": "separate production-derived Swift executables", "framing": "4-byte big-endian length followed by raw payload bytes over stdout/stdin", "directions": ["mac-encoder-to-ios-decoder", "ios-encoder-to-mac-decoder"], "negativeCases": ["zero-length frame exits nonzero", "production-derived adversarial case mode exits nonzero on unexpected acceptance"]}
AVAILABILITY = "outside automated matrix evidence DAG; S-P1-05 OPEN-WAIVED"
def die(message):
    raise SystemExit("FAIL_CLOSED: " + message)
def sha(data):
    return hashlib.sha256(data).hexdigest()
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
def hexv(value, length): return isinstance(value, str) and len(value) == length and set(value) <= HEX64
PUBLIC_INVENTORY_KEYS = {"logical", "generated", "package", "cache"}
def public_inventory(value, label):
    if (not isinstance(value, dict) or set(value) != {"inventorySha256", "fullInventorySha256", "inventoryEntryCounts", "inventoryEntries"}
            or not isinstance(value["inventorySha256"], dict) or set(value["inventorySha256"]) != PUBLIC_INVENTORY_KEYS
            or any(not hexv(item, 64) for item in value["inventorySha256"].values())
            or not hexv(value["fullInventorySha256"], 64)
            or not isinstance(value["inventoryEntryCounts"], dict) or set(value["inventoryEntryCounts"]) != PUBLIC_INVENTORY_KEYS
            or any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in value["inventoryEntryCounts"].values())
            or not isinstance(value["inventoryEntries"], dict) or set(value["inventoryEntries"]) != PUBLIC_INVENTORY_KEYS):
        die(label + " public inventory fields are invalid")
    seen = set()
    for category in PUBLIC_INVENTORY_KEYS:
        entries = value["inventoryEntries"][category]
        if not isinstance(entries, list) or value["inventoryEntryCounts"][category] != len(entries) or entries != sorted(entries, key=lambda entry: entry.get("path") if isinstance(entry, dict) else ""):
            die(label + " inventory entries are not sorted")
        for entry in entries:
            if (not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size", "dev", "ino"} or not isinstance(entry["path"], str) or not entry["path"] or Path(entry["path"]).is_absolute() or any(part in ("", ".", "..") for part in Path(entry["path"]).parts) or entry["path"] in seen or not hexv(entry["sha256"], 64) or any(not isinstance(entry[key], int) or isinstance(entry[key], bool) or entry[key] < 0 for key in ("size", "dev", "ino"))):
                die(label + " inventory entry is invalid")
            seen.add(entry["path"])
        if value["inventorySha256"][category] != sha(canonical(entries)):
            die(label + " inventory category digest mismatch")
    if value["fullInventorySha256"] != sha(canonical(value["inventoryEntries"])): die(label + " full inventory digest mismatch")
def exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields): die(label + " fields are not exact")
def load(path):
    try:
        raw = Path(path).read_bytes()
        def pairs(items):
            out = {}
            for key, value in items:
                if key in out: raise ValueError("duplicate key " + key)
                out[key] = value
            return out
        return raw, json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc: die("malformed record " + str(path) + ": " + str(exc))
def open_evidence_root(path):
    try:
        before = Path(path).lstat()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
    except OSError as exc:
        die("evidence root is unavailable: " + str(exc))
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode) or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
        os.close(fd); die("evidence root is unstable")
    return fd
def read_evidence(rootfd, relative, label):
    parts = Path(relative).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        die(label + " has invalid relative path")
    fd = os.dup(rootfd)
    try:
        for part in parts[:-1]:
            nextfd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            os.close(fd); fd = nextfd
        leaf = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
        try:
            info = os.fstat(leaf)
            if not stat.S_ISREG(info.st_mode): die(label + " is not a regular evidence file")
            data = os.read(leaf, info.st_size + 1)
            if len(data) != info.st_size or os.fstat(leaf).st_size != info.st_size: die(label + " changed while reading")
            return data
        finally:
            os.close(leaf)
    except OSError as exc:
        die(label + " is unavailable: " + str(exc))
    finally:
        os.close(fd)
def load_bytes(raw, label):
    try:
        def pairs(items):
            out = {}
            for key, value in items:
                if key in out: raise ValueError("duplicate key " + key)
                out[key] = value
            return out
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        die("malformed record " + label + ": " + str(exc))
def copy_exclusive_at(rootfd, relative, data):
    parts = Path(relative).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        die("evidence output has invalid relative path")
    fd = os.dup(rootfd)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            nextfd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            os.close(fd); fd = nextfd
        leaf = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=fd)
        try:
            os.write(leaf, data); os.fsync(leaf)
        finally:
            os.close(leaf)
    except FileExistsError:
        die("refusing to overwrite evidence " + relative)
    except OSError as exc:
        die("evidence output is unavailable: " + str(exc))
    finally:
        os.close(fd)
def git(root, argv):
    result = subprocess.run(["git", "-C", str(root), *argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode: die("source binding query failed for " + str(root))
    return result.stdout.decode("ascii", "strict").strip()
def open_source_roots(roots):
    handles = {}
    for ident, root in roots.items():
        try:
            before = root.lstat()
            fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
            info = os.fstat(fd)
        except OSError as exc: die("source root is unavailable: " + str(exc))
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode) or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
            os.close(fd); die("source root identity is unstable")
        handles[ident] = (fd, (info.st_dev, info.st_ino))
    return handles
def source_manifest(handles):
    """Traverse retained no-follow root descriptors and hash each regular file from its opened fd."""
    manifests = {}
    def scan(fd, root_dev, prefix, entries):
        here = os.fstat(fd)
        if not stat.S_ISDIR(here.st_mode) or here.st_dev != root_dev: die("source directory identity changed")
        for name in sorted(os.listdir(fd)):
            if name in (".", ".."): continue
            relative = prefix + name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode): die("source inventory rejects symlink: " + relative)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
                try:
                    child_info = os.fstat(child)
                    if (child_info.st_dev, child_info.st_ino) != (info.st_dev, info.st_ino): die("source directory changed while opening")
                    entries[relative] = ("directory", info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
                    scan(child, root_dev, relative + "/", entries)
                finally: os.close(child)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1: die("source inventory rejects hardlinked file: " + relative)
                child = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_nlink) != (info.st_dev, info.st_ino, info.st_size, 1): die("source file changed while opening")
                    chunks = []
                    while True:
                        chunk = os.read(child, 1024 * 1024)
                        if not chunk: break
                        chunks.append(chunk)
                    if os.fstat(child).st_size != info.st_size: die("source file changed while reading")
                    entries[relative] = ("file", info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, sha(b"".join(chunks)))
                finally: os.close(child)
            else: die("source inventory rejects unsupported entry: " + relative)
    for ident, (fd, identity) in handles.items():
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != identity: die("source root identity changed")
            entries = {}; scan(fd, identity[0], "", entries); manifests[ident] = entries
        except OSError as exc: die("source inventory descriptor traversal failed: " + str(exc))
    return manifests
def derived_public_inventory(handles, sealed):
    manifest=source_manifest(handles)
    derived={}
    for ident, entries in manifest.items():
        public=sealed[ident]; public_inventory(public, "sealed public inventory")
        actual={}
        for path, value in entries.items():
            if value[0] == "file":
                actual[path]={"sha256":value[-1],"size":value[3],"dev":value[1],"ino":value[2]}
        declared={entry["path"]:entry for category in public["inventoryEntries"].values() for entry in category}
        if set(actual) != set(declared): die("sealed public inventory entries have missing or extra paths")
        if any(actual[path] != {key:declared[path][key] for key in ("sha256","size","dev","ino")} for path in actual): die("sealed public inventory entry identity or content mismatch")
        derived[ident]=public
    return derived
def require_unchanged_manifest(manifest, handles):
    if source_manifest(handles) != manifest: die("source tree, including .git and ignored/generated entries, changed during sealed matrix execution")
def require_external_evidence_root(evidence, roots):
    if any(evidence == root or root in evidence.parents for root in roots.values()):
        die("evidence root must be an explicit external output, outside every source root")
def require_clean_tuple(roots, tuple_):
    for ident, root in roots.items():
        if not root.is_dir() or git(root, ["rev-parse", "HEAD"]) != tuple_[ident + "Commit"]:
            die(ident + " root is not the exact clean tuple")
        for argv in (["diff-index", "--quiet", "HEAD", "--"], ["diff-files", "--quiet"], ["ls-files", "--others", "--exclude-standard"]):
            result = subprocess.run(["git", "-C", str(root), *argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
            if result.returncode or (argv[0] == "ls-files" and result.stdout): die(ident + " root is not the exact clean tuple")
def validate_pin(pin, tuple_):
    exact(pin, PIN_FIELDS, "inner build pin")
    return pin.get("schemaVersion") == 1 and pin.get("protocolCommit") == tuple_["protocolCommit"] and pin.get("compatibilityDigest") == tuple_["compatibilityDigest"] and pin.get("normativeManifestDigest") == tuple_["normativeManifestDigest"]
def nonempty_unique(values, label):
    if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values) or len(set(values)) != len(values): die(label + " must be a nonempty unique string list")
def validate_inner(value, tuple_):
    exact(value, INNER_FIELDS, "inner matrix")
    if value.get("schemaVersion") != 2 or value.get("kind") != "cross-repo-production-interop-report" or value.get("result") != "passed" or value.get("sourceTuple") != tuple_: die("inner matrix is not a complete passing production report")
    coverage = value["coverageContract"]; exact(coverage, COVERAGE_FIELDS, "inner coverage contract")
    for key in ("positiveRawFrameCases", "enumeratedProtocolPositiveVectorIDs", "enumeratedProtocolNegativeVectorIDs", "productionSuiteCoveredPositiveVectorIDs", "productionSuiteCoveredNegativeVectorIDs", "negativeVectorEvidenceLabels", "positiveVectorEvidenceLabels"): nonempty_unique(coverage[key], "inner " + key)
    if coverage["productionSuiteCoveredPositiveVectorIDs"] != coverage["enumeratedProtocolPositiveVectorIDs"] or coverage["productionSuiteCoveredNegativeVectorIDs"] != coverage["enumeratedProtocolNegativeVectorIDs"] or coverage["unexecutableNegativeVectorIDs"] != [] or set(coverage["negativeVectorEvidenceLabels"]) != NEGATIVE_LABELS or set(coverage["positiveVectorEvidenceLabels"]) != POSITIVE_LABELS or coverage["unexecutablePolicy"] != "matrix fails rather than claiming vector coverage without passing production suites": die("inner coverage semantics are incomplete")
    adversarial = coverage["productionDerivedAdversarialCases"]
    if set(adversarial) != {"mac", "ios"} or any(not isinstance(adversarial[x], list) or set(adversarial[x]) != set(coverage["enumeratedProtocolNegativeVectorIDs"]) for x in adversarial): die("inner adversarial coverage is incomplete")
    suites = coverage["productionSuiteResults"]
    if not isinstance(suites, dict) or set(suites) != NEGATIVE_LABELS | POSITIVE_LABELS or any(v is not True for v in suites.values()): die("inner production suite evidence is incomplete")
    exact(value["processProtocol"], set(PROCESS), "inner process protocol")
    if value["processProtocol"] != PROCESS: die("inner process protocol is invalid")
    pins = value["builtPinEvidence"]; exact(pins, {"trackedConsumerPins", "builtProductPins", "trackedConsumerPinSha256", "builtProductPinSha256"}, "inner built pin evidence")
    for key in ("trackedConsumerPins", "builtProductPins"):
        if not isinstance(pins[key], dict) or set(pins[key]) != {"mac", "ios"} or any(not validate_pin(pin, tuple_) for pin in pins[key].values()): die("inner pin evidence is invalid")
    for key in ("trackedConsumerPinSha256", "builtProductPinSha256"):
        if not isinstance(pins[key], dict) or set(pins[key]) != {"mac", "ios"} or any(not hexv(v, 64) for v in pins[key].values()): die("inner pin hash references are invalid")
    if pins["trackedConsumerPins"] != pins["builtProductPins"] or pins["trackedConsumerPinSha256"] != pins["builtProductPinSha256"]: die("inner built pin evidence does not bind tracked pins")
    commands = value["commands"]
    if not isinstance(commands, list) or not commands or not isinstance(value["failures"], list) or value["failures"]: die("inner matrix result details are invalid")
    paths = set()
    for command in commands:
        exact(command, {"label", "exitCode", "logPath"}, "inner command")
        if not isinstance(command["label"], str) or not command["label"] or command["exitCode"] != 0 or not isinstance(command["logPath"], str) or not command["logPath"].startswith("logs/") or "/" in command["logPath"][5:]: die("inner command evidence is invalid")
        paths.add(command["logPath"])
    if len(paths) != len(commands): die("inner command log paths are not unique")
    for key in ("compatibilityReceipt", "freshCompatibilityReceipt"):
        exact(value[key], {"path", "sha256"}, "inner " + key)
        if not isinstance(value[key]["path"], str) or not value[key]["path"] or "/" in value[key]["path"] or not hexv(value[key]["sha256"], 64): die("inner receipt is invalid")
    if value["compatibilityReceipt"]["path"] != "compatibility-report.json" or value["freshCompatibilityReceipt"]["path"] != "compatibility-report-fresh.json" or value["physicalAvailability"] != AVAILABILITY: die("inner compatibility or availability evidence is invalid")
    return paths

def open_lifecycle(directory):
    try:
        before=Path(directory).lstat(); fd=os.open(directory, os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)); info=os.fstat(fd)
    except OSError as exc: die("lifecycle directory is unavailable: " + str(exc))
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode) or (before.st_dev,before.st_ino)!=(info.st_dev,info.st_ino): os.close(fd); die("lifecycle directory is unstable")
    return fd, (info.st_dev, info.st_ino)
def lifecycle_admission(handle, ident, tuple_):
    """Enumerate and read only via the retained no-follow lifecycle dirfd."""
    dfd, identity=handle
    current=os.fstat(dfd)
    if (current.st_dev,current.st_ino)!=identity: die("lifecycle directory identity changed")
    names=set(os.listdir(dfd)); expected={"000-allocated.json","010-source-active.json"}
    if names != expected: die("lifecycle admission requires exactly allocated and source-active states")
    raws={}
    for name in expected:
        fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=dfd)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode): die("lifecycle state is not regular")
            data=os.read(fd,info.st_size+1)
            if len(data)!=info.st_size or os.fstat(fd).st_size!=info.st_size: die("lifecycle state changed while reading")
            raws[name]=data
        finally: os.close(fd)
    allocated=parse_lifecycle(raws["000-allocated.json"],"allocated"); active=parse_lifecycle(raws["010-source-active.json"],"source-active")
    if active["predecessorSha256"]!=sha(raws["000-allocated.json"]): die("source-active predecessor CAS mismatch")
    if any(active[k]!=allocated[k] for k in ("lifecycleId","rootId","tuple","allocation","authority")): die("lifecycle state lineage mismatch")
    if active["rootId"]!=ident or active["tuple"]!={k:tuple_[k] for k in ("macCommit","iosCommit","protocolCommit")}: die("lifecycle tuple mismatch")
    return {"allocated":raws["000-allocated.json"],"active":raws["010-source-active.json"],"snapshot":canonical({"entries":sorted(expected),"dev":identity[0],"ino":identity[1]}),"record":active}
def require_unchanged_lifecycle(lifecycle, handles, tuple_):
    for ident,handle in zip(IDS,handles):
        current=lifecycle_admission(handle,ident,tuple_); prior=lifecycle[ident]
        if any(current[k]!=prior[k] for k in ("allocated","active","snapshot")): die("lifecycle admission changed during sealed matrix execution")
def parse_lifecycle(raw, state):
    try: value=json.loads(raw.decode("utf-8"))
    except Exception as exc: die("malformed lifecycle state: " + str(exc))
    fields={"schemaVersion","kind","lifecycleId","rootId","tuple","allocation","authority","state","predecessorSha256"}
    if state == "source-active": fields.add("allocationReleaseSha256")
    if not isinstance(value,dict) or set(value)!=fields or value.get("schemaVersion")!=1 or value.get("kind")!="photonport.lifecycle-state.v1" or value.get("state")!=state: die("invalid lifecycle state")
    if state == "source-active" and not hexv(value["allocationReleaseSha256"],64): die("invalid allocation release binding")
    return value

def mutex_payload(payload, ident, root):
    exact(payload, {"lifecycleId", "rootId", "allocation", "authority", "allocationNonce", "mutexNonce", "supervisor", "rootDev", "rootIno", "mutexDev", "mutexIno", "supervisorFdDev", "supervisorFdIno", "closeSecretSha256", "acquisitionTag"}, "source mutex")
    if payload["rootId"] != ident or payload["rootDev"] != root.st_dev or payload["rootIno"] != root.st_ino or not isinstance(payload["lifecycleId"], str) or not payload["lifecycleId"] or not isinstance(payload["allocation"], dict) or set(payload["allocation"]) != {"id", "sha256"} or not isinstance(payload["allocation"]["id"], str) or not payload["allocation"]["id"] or not hexv(payload["allocation"]["sha256"], 64) or not hexv(payload["allocationNonce"], 64) or not hexv(payload["mutexNonce"], 64) or not isinstance(payload["supervisor"], str) or not payload["supervisor"]: die("source mutex capability is invalid")
def acquire_mutexes(paths, roots, active, supervisor_fds, secret_fds):
    """Consume supervisor-owned Lock-B descriptors; never acquire/flock a new lock."""
    held = []
    try:
        for ident, path, fd, secret_fd in zip(IDS, paths, supervisor_fds, secret_fds):
            path = Path(path)
            state = active[ident][1]
            expected = Path(state["authority"]["lockBPath"])
            if path.resolve() != expected:
                die("source mutex path is not the authority-bound canonical Lock-B path for " + ident)
            info = os.fstat(fd); named = path.stat(); root = roots[ident].stat(); raw, payload = load(path)
            if (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino): die("inherited supervisor capability does not name canonical Lock-B for " + ident)
            mutex_payload(payload, ident, root)
            secret = os.pread(secret_fd, 33, 0)
            if len(secret) != 32 or hashlib.sha256(secret).hexdigest() != payload["closeSecretSha256"]:
                die("supervisor close capability does not match acquisition binding")
            unsigned = dict(payload); tag = unsigned.pop("acquisitionTag")
            if not hmac.compare_digest(tag, hmac.new(secret, canonical(unsigned), hashlib.sha256).hexdigest()):
                die("supervisor acquisition capability tag is invalid")
            if (payload["mutexDev"], payload["mutexIno"], payload["supervisorFdDev"], payload["supervisorFdIno"]) != (info.st_dev, info.st_ino, info.st_dev, info.st_ino):
                die("supervisor capability identity is not acquisition-bound")
            if (payload["lifecycleId"] != state["lifecycleId"] or payload["allocation"] != state["allocation"] or payload["authority"] != state["authority"] or payload["rootDev"] != state["authority"]["root"]["dev"] or payload["rootIno"] != state["authority"]["root"]["ino"] ):
                die("source mutex is not immutably bound to source-active record")
            held.append((ident, path, fd, info.st_dev, info.st_ino, root.st_dev, root.st_ino, raw))
        return held
    except Exception:
        # Descriptors are owned by the supervisor; this matrix process never closes them.
        raise
def require_held_mutexes(held, roots):
    for ident, path, fd, dev, ino, root_dev, root_ino, raw in held:
        try:
            current = path.stat()
            opened = os.fstat(fd)
            root = roots[ident].stat()
            probe = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            die("source mutex capability is unavailable: " + str(exc))
        try:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                held_by_inherited_capability = True
            else:
                held_by_inherited_capability = False
        finally:
            os.close(probe)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            inherited_fd_is_holder = False
        else:
            inherited_fd_is_holder = True
        if ((current.st_dev, current.st_ino) != (dev, ino)
                or (opened.st_dev, opened.st_ino) != (dev, ino)
                or (root.st_dev, root.st_ino) != (root_dev, root_ino)
                or sha(path.read_bytes()) != sha(raw)
                or not held_by_inherited_capability
                or not inherited_fd_is_holder):
            die("source mutex capability is unlocked, unrelated, replaced, or root identity changed")
def seatbelt_profile(evidence, roots, command):
    sandbox = evidence / "sandboxes" / ("TX-" + hashlib.sha256(os.urandom(32)).hexdigest())
    sandbox.mkdir(parents=True, exist_ok=False)
    if any(root == sandbox or root in sandbox.parents for root in roots.values()): die("sandbox must be external to source roots")
    profile = sandbox / "seatbelt.sb"
    output = evidence / "inner-matrix.json"; receipts = evidence / "receipts"; logs = evidence / "logs"
    compatibility = evidence / "compatibility-report.json"; fresh_compatibility = evidence / "compatibility-report-fresh.json"
    receipts.mkdir(exist_ok=True); logs.mkdir(exist_ok=True)
    grants = [str(sandbox), str(output), str(receipts), str(logs), str(compatibility), str(fresh_compatibility)]
    for path in (sandbox, output.parent, receipts, logs):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode): die("evidence output ancestry is unsafe")
    lines = ["(version 1)", "(deny default)", '(allow process*)', '(allow file-read*)',
             '(allow file-write* (subpath "' + str(sandbox) + '"))',
             '(allow file-write* (literal "' + str(output) + '"))',
             '(allow file-write* (subpath "' + str(receipts) + '"))',
             '(allow file-write* (subpath "' + str(logs) + '"))',
             '(allow file-write* (literal "' + str(compatibility) + '"))',
             '(allow file-write* (literal "' + str(fresh_compatibility) + '"))']
    profile.write_text("\n".join(lines) + "\n", encoding="utf-8")
    raw = profile.read_bytes()
    if not Path("/usr/bin/sandbox-exec").is_file(): die("mandatory sandbox-exec is unavailable")
    env = {"HOME": str(sandbox / "home"), "TMPDIR": str(sandbox / "tmp"), "CLANG_MODULE_CACHE_PATH": str(sandbox / "cache"), "SWIFTPM_DISABLE_AUTOMATIC_RESOLUTION": "1"}
    for path in (env["HOME"], env["TMPDIR"], env["CLANG_MODULE_CACHE_PATH"]): Path(path).mkdir(parents=True, exist_ok=True)
    return sandbox, profile, raw, env, grants
def inventory(handle):
    """Descriptor-visible logical inventory including generated/package/cache inputs."""
    return canonical({"schemaVersion":1,"entries":source_manifest({"root": handle})["root"]})
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mac-root", required=True); p.add_argument("--ios-root", required=True); p.add_argument("--protocol-root", required=True)
    p.add_argument("--expected-mac-commit", required=True); p.add_argument("--expected-ios-commit", required=True); p.add_argument("--expected-protocol-commit", required=True)
    p.add_argument("--expected-compatibility-digest", required=True); p.add_argument("--expected-normative-manifest-digest", required=True)
    p.add_argument("--supervisor-close-secret-fd", nargs=3, type=int, required=True); p.add_argument("--lifecycle-directory", nargs=3, required=True); p.add_argument("--seal-manifest", nargs=3, required=True); p.add_argument("--live-attestation", nargs=3, required=True); p.add_argument("--source-mutex", nargs=3, required=True); p.add_argument("--supervisor-fd", nargs=3, type=int, required=True, help="inherited Lock-B capabilities, held by the supervisor")
    p.add_argument("--evidence-root", required=True); p.add_argument("--test-only-inner-command", nargs=argparse.REMAINDER, help="test-only override")
    a = p.parse_args()
    if a.test_only_inner_command is not None and not a.test_only_inner_command: die("test-only inner command must not be empty")
    tuple_ = {"macCommit": a.expected_mac_commit, "iosCommit": a.expected_ios_commit, "protocolCommit": a.expected_protocol_commit, "compatibilityDigest": a.expected_compatibility_digest, "normativeManifestDigest": a.expected_normative_manifest_digest}
    if not all(hexv(v, 40 if k.endswith("Commit") else 64) for k, v in tuple_.items()): die("tuple contains invalid lowercase full hex")
    roots = {"mac": Path(a.mac_root).resolve(), "ios": Path(a.ios_root).resolve(), "protocol": Path(a.protocol_root).resolve()}
    handles = [open_lifecycle(path) for path in a.lifecycle_directory]
    lifecycle = {ident: lifecycle_admission(handle, ident, tuple_) for ident, handle in zip(IDS, handles)}
    values = []
    for paths, kind, fields in ((a.seal_manifest, "seal-manifest-v1", {"schemaVersion", "kind", "id", "commit", "sourceActiveSha256", "inventorySha256", "fullInventorySha256", "inventoryEntryCounts", "inventoryEntries"}), (a.live_attestation, "live-attestation-v1", {"schemaVersion", "kind", "id", "commit", "sealManifestSha256", "inventorySha256", "fullInventorySha256", "inventoryEntryCounts", "inventoryEntries"})):
        seen = {}
        for path in paths:
            raw, value = load(path); exact(value, fields, kind)
            if value.get("schemaVersion") != 1 or value.get("kind") != kind or value.get("id") not in IDS or not hexv(value.get("commit"), 40) or value["id"] in seen: die("invalid or duplicate " + kind + " record")
            public_inventory({key:value[key] for key in ("inventorySha256", "fullInventorySha256", "inventoryEntryCounts", "inventoryEntries")}, kind)
            seen[value["id"]] = (raw, value, Path(path).resolve())
        if set(seen) != set(IDS): die(kind + " records must contain exactly mac, ios, protocol")
        values.append(seen)
    seals, attestations = values
    active = {ident: (lifecycle[ident]["active"], lifecycle[ident]["record"], Path(a.lifecycle_directory[IDS.index(ident)]).resolve()) for ident in IDS}
    for ident in IDS:
        state = active[ident][1]
        if seals[ident][1].get("commit") != tuple_[ident + "Commit"] or attestations[ident][1].get("commit") != tuple_[ident + "Commit"]: die("lifecycle/live attestation tuple mismatch for " + ident)
        if not hexv(seals[ident][1].get("sourceActiveSha256"), 64) or seals[ident][1]["sourceActiveSha256"] != sha(active[ident][0]) or not hexv(attestations[ident][1].get("sealManifestSha256"), 64) or attestations[ident][1]["sealManifestSha256"] != sha(seals[ident][0]) or any(seals[ident][1][key] != attestations[ident][1][key] for key in ("inventorySha256", "fullInventorySha256", "inventoryEntryCounts", "inventoryEntries")): die("seal chain or public inventory mismatch for " + ident)
    held = acquire_mutexes(a.source_mutex, roots, active, a.supervisor_fd, a.supervisor_close_secret_fd)
    try:
        require_held_mutexes(held, roots); require_unchanged_lifecycle(lifecycle, handles, tuple_)
        require_clean_tuple(roots, tuple_)
        evidence = Path(a.evidence_root).resolve(); require_external_evidence_root(evidence, roots); evidence.mkdir(parents=True, exist_ok=True); evidence_fd = open_evidence_root(evidence); root_handles = open_source_roots(roots); sealed_public_inventories={ident:{key:seals[ident][1][key] for key in ("inventorySha256", "fullInventorySha256", "inventoryEntryCounts", "inventoryEntries")} for ident in IDS}; derived_public=derived_public_inventory(root_handles, sealed_public_inventories)
        if derived_public != sealed_public_inventories: die("sealed public inventory does not match retained source root")
        manifest = source_manifest(root_handles); inventories = {ident: inventory(root_handles[ident]) for ident in IDS}; records = []
        for name, group in (("source-active", active), ("seal-manifest", seals), ("live-attestation", attestations)):
            for ident in IDS:
                relative = "inputs/" + name + "-" + ident + ".json"; raw = group[ident][0]; copy_exclusive_at(evidence_fd, relative, raw); records.append({"role": name + ":" + ident, "path": relative, "sha256": sha(raw)})
        for ident in IDS:
            for role, raw in (("lifecycle-allocated", lifecycle[ident]["allocated"]), ("lifecycle-admission", lifecycle[ident]["snapshot"])):
                relative = "inputs/" + role + "-" + ident + ".json"; copy_exclusive_at(evidence_fd, relative, raw); records.append({"role": role + ":" + ident, "path": relative, "sha256": sha(raw)})
        for ident, raw in inventories.items():
            relative = "inputs/inventory-" + ident + ".json"; copy_exclusive_at(evidence_fd, relative, raw)
            records.append({"role": "inventory:" + ident, "path": relative, "sha256": sha(raw)})
        mutex_bindings = []
        for ident, _, _, _, _, _, _, raw in held:
            relative = "inputs/source-mutex-" + ident + ".json"; copy_exclusive_at(evidence_fd, relative, raw)
            records.append({"role": "source-mutex:" + ident, "path": relative, "sha256": sha(raw)})
            payload = load_bytes(raw, "source mutex")
            mutex_bindings.append({"id": ident, "canonicalPath": MUTEX_NAME, "sourceActiveSha256": sha(active[ident][0]), "sealManifestSha256": sha(seals[ident][0]), "mutexSha256": sha(raw), **payload})
        inner = evidence / "inner-matrix.json"; test_only = a.test_only_inner_command is not None; command = a.test_only_inner_command if test_only else [str(PRODUCTION_RUNNER)]
        command = [*command, "--mac-root", str(roots["mac"]), "--ios-root", str(roots["ios"]), "--protocol-root", str(roots["protocol"]), "--expected-mac-commit", tuple_["macCommit"], "--expected-ios-commit", tuple_["iosCommit"], "--expected-protocol-commit", tuple_["protocolCommit"], "--expected-compatibility-digest", tuple_["compatibilityDigest"], "--expected-normative-manifest-digest", tuple_["normativeManifestDigest"], "--output", str(inner)]
        if test_only:
            profile_raw = b""
            containment = {"profileFormat":"seatbelt-v1","mode":"test-only","result":"not-production","allowedWritePaths":[],"argvSha256":sha(canonical(command)),"environmentSha256":sha(canonical({}))}
            completed = subprocess.run(command, cwd=str(evidence))
            transcript_body = b""
        else:
            sandbox, profile, profile_raw, sandbox_env, grants = seatbelt_profile(evidence, roots, command)
            command = ["/usr/bin/sandbox-exec", "-f", str(profile), "--", *command]
            completed = subprocess.run(command, cwd=str(evidence), env={**os.environ, **sandbox_env}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            containment = {"profileFormat":"seatbelt-v1","mode":"source-read-only","result":"enforced","allowedWritePaths":grants,"argvSha256":sha(canonical(command)),"environmentSha256":sha(canonical(sandbox_env))}
            transcript_body = completed.stdout
        containment["profileSha256"] = sha(profile_raw)
        transcript_raw = canonical({"argvSha256":containment["argvSha256"],"environmentSha256":containment["environmentSha256"],"profileSha256":containment["profileSha256"]}) + b"\n" + transcript_body
        copy_exclusive_at(evidence_fd, "containment/seatbelt.sb", profile_raw)
        copy_exclusive_at(evidence_fd, "containment/process-transcript.log", transcript_raw)
        containment["profile"] = {"path":"containment/seatbelt.sb","sha256":sha(profile_raw),"size":len(profile_raw)}
        containment["processTranscript"] = {"path":"containment/process-transcript.log","sha256":sha(transcript_raw),"size":len(transcript_raw)}
        containment["processTranscriptSha256"] = sha(transcript_raw)
        require_held_mutexes(held, roots); require_unchanged_manifest(manifest, root_handles); require_unchanged_lifecycle(lifecycle, handles, tuple_)
        if any(inventory(root_handles[ident]) != inventories[ident] for ident in IDS) or derived_public_inventory(root_handles, sealed_public_inventories) != sealed_public_inventories: die("logical/generated/package/cache inventory changed during matrix execution")
        raw_inner = read_evidence(evidence_fd, "inner-matrix.json", "inner matrix report"); value_inner = load_bytes(raw_inner, "inner matrix report"); command_paths = validate_inner(value_inner, tuple_); require_held_mutexes(held, roots); require_unchanged_manifest(manifest, root_handles); require_unchanged_lifecycle(lifecycle, handles, tuple_)
        if any(inventory(root_handles[ident]) != inventories[ident] for ident in IDS) or derived_public_inventory(root_handles, sealed_public_inventories) != sealed_public_inventories: die("logical/generated/package/cache inventory changed during matrix execution")
        for key, role in (("compatibilityReceipt", "compatibility-receipt"), ("freshCompatibilityReceipt", "fresh-compatibility-receipt")):
            receipt = value_inner[key]
            raw = read_evidence(evidence_fd, receipt["path"], "inner " + key)
            if sha(raw) != receipt["sha256"]: die("inner " + key + " hash mismatch")
            relative = "receipts/" + receipt["path"]; copy_exclusive_at(evidence_fd, relative, raw)
            records.append({"role": role, "path": relative, "sha256": sha(raw)})
        logs = []
        try:
            logs_fd = os.open("logs", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=evidence_fd)
            log_names = sorted(os.listdir(logs_fd))
        except OSError:
            log_names = []
        finally:
            if 'logs_fd' in locals(): os.close(logs_fd)
        for name in log_names:
            if not name.endswith(".json") or "/" in name: continue
            relative = "logs/" + name; raw = read_evidence(evidence_fd, relative, "matrix log"); logs.append({"path": relative, "sha256": sha(raw)})
        if command_paths != {log["path"] for log in logs}: die("inner command evidence does not exactly bind sealed logs")
        result = "passed" if completed.returncode == 0 else "failed"
        runner_sha = sha(PRODUCTION_RUNNER.read_bytes())
        provenance = {"mode": "test-only" if test_only else "production", "runnerPath": "test-only-inner-command" if test_only else "scripts/run-cross-repo-matrix.py", "runnerSha256": sha("\0".join(command).encode()) if test_only else runner_sha}
        kind = "photonport.sealed-cross-repo-matrix.test-only.v1" if test_only else "photonport.sealed-cross-repo-matrix.v1"
        public_inventories={ident:{key:seals[ident][1][key] for key in ("inventorySha256", "fullInventorySha256", "inventoryEntryCounts", "inventoryEntries")} for ident in IDS}
        report = {"schemaVersion": 1, "kind": kind, "result": result, "sourceTuple": tuple_, "provenance": provenance, "containment": containment, "inventories": {ident: sha(raw) for ident, raw in inventories.items()}, "publicInventories": public_inventories, "records": records, "mutexBindings": mutex_bindings, "innerMatrix": {"path": "inner-matrix.json", "sha256": sha(raw_inner)}, "logs": logs}
        require_held_mutexes(held, roots); require_unchanged_manifest(manifest, root_handles); require_unchanged_lifecycle(lifecycle, handles, tuple_)
        report_raw=(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
        binding={"schemaVersion":1,"kind":"photonport.matrix-binding.v1","reportSha256":sha(report_raw),"reportSize":len(report_raw),"tupleSha256":sha(canonical(tuple_)),"lifecycleTupleSha256":sha(canonical({key:tuple_[key] for key in ("macCommit","iosCommit","protocolCommit")})),"inventorySha256ByRoot":{i:seals[i][1]["inventorySha256"] for i in IDS},"fullInventorySha256ByRoot":{i:seals[i][1]["fullInventorySha256"] for i in IDS},"inventoryEntryCountsByRoot":{i:seals[i][1]["inventoryEntryCounts"] for i in IDS},"inventoryEntriesSha256ByRoot":{i:sha(canonical(seals[i][1]["inventoryEntries"])) for i in IDS},"allocatedSha256ByRoot":{i:sha(lifecycle[i]["allocated"]) for i in IDS},"sourceActiveSha256ByRoot":{i:sha(lifecycle[i]["active"]) for i in IDS},"sealSha256ByRoot":{i:sha(seals[i][0]) for i in IDS},"mutexSha256ByRoot":{i:sha(next(x[7] for x in held if x[0]==i)) for i in IDS},"containmentSha256":sha(canonical(containment)),"innerMatrixSha256":sha(raw_inner),"logsSha256":sha(canonical(logs))}
        copy_exclusive_at(evidence_fd, "sealed-matrix.json", report_raw); copy_exclusive_at(evidence_fd, "matrix-binding.json", (json.dumps(binding,sort_keys=True,separators=(",",":"))+"\n").encode()); return 0 if completed.returncode == 0 else 1
    finally:
        # Lock-B descriptor lifetime belongs to the supervisor.
        if 'root_handles' in locals():
            for fd, _ in root_handles.values(): os.close(fd)
        if 'evidence_fd' in locals(): os.close(evidence_fd)
        for fd, _ in handles: os.close(fd)
if __name__ == "__main__": sys.exit(main())
