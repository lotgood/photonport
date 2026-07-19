#!/usr/bin/env python3
"""Fail-closed verifier for R01 fresh Xcode generation/build evidence."""
import argparse, hashlib, json, os, plistlib, stat, subprocess, sys
from pathlib import Path

HEX = set("0123456789abcdef")
IDS = ("mac", "ios", "protocol")
TUPLE = ("macCommit", "iosCommit", "protocolCommit", "compatibilityDigest", "normativeManifestDigest")

def die(message): raise SystemExit("FAIL_CLOSED: " + message)
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
def sha(data): return hashlib.sha256(data).hexdigest()
def hex64(value): return isinstance(value, str) and len(value) == 64 and set(value) <= HEX
def exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields): die(label + " fields are not exact")
def relpath(value, label):
    if not isinstance(value, str) or not value or Path(value).is_absolute() or any(x in ("", ".", "..") for x in Path(value).parts): die(label + " path is invalid")
    return value
def parse(raw, label):
    try:
        def pairs(items):
            out = {}
            for key, value in items:
                if key in out: raise ValueError("duplicate key " + key)
                out[key] = value
            return out
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc: die(label + " is malformed: " + str(exc))
def open_root(path):
    try:
        before = Path(path).lstat(); fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)); after = os.fstat(fd)
    except OSError as exc: die("evidence root unavailable: " + str(exc))
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino): os.close(fd); die("evidence root identity is unstable")
    return fd
def read_at(rootfd, relative, label):
    parts = Path(relpath(relative, label)).parts; fd = os.dup(rootfd)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd); os.close(fd); fd = nxt
        leaf = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
        try:
            info = os.fstat(leaf)
            if not stat.S_ISREG(info.st_mode): die(label + " is not regular")
            raw = os.read(leaf, info.st_size + 1)
            if len(raw) != info.st_size or os.fstat(leaf).st_size != info.st_size: die(label + " changed while reading")
            return raw
        finally: os.close(leaf)
    except OSError as exc: die(label + " unavailable: " + str(exc))
    finally: os.close(fd)
def artifact(rootfd, ref, label):
    exact(ref, ("path", "sha256", "size"), label)
    raw = read_at(rootfd, ref["path"], label)
    if not hex64(ref["sha256"]) or not isinstance(ref["size"], int) or isinstance(ref["size"], bool) or ref["size"] < 0 or len(raw) != ref["size"] or sha(raw) != ref["sha256"]: die(label + " digest mismatch")
    return raw
def tree(rootfd, relative, label):
    """Hash a no-follow directory as sorted canonical file entries."""
    parts = Path(relpath(relative, label)).parts; fd = os.dup(rootfd); entries = []
    try:
        for part in parts:
            nxt = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd); os.close(fd); fd = nxt
        def walk(directory, prefix):
            for name in sorted(os.listdir(directory)):
                info = os.stat(name, dir_fd=directory, follow_symlinks=False); path = prefix + name
                if stat.S_ISLNK(info.st_mode) or info.st_nlink != 1: die(label + " contains symlink or hardlink")
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
                    try:
                        opened = os.fstat(child)
                        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino): die(label + " directory changed")
                        walk(child, path + "/")
                    finally: os.close(child)
                elif stat.S_ISREG(info.st_mode):
                    child = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
                    try:
                        data = b""
                        while True:
                            chunk = os.read(child, 1024 * 1024)
                            if not chunk: break
                            data += chunk
                        if os.fstat(child).st_size != info.st_size: die(label + " file changed")
                        entries.append({"path": path, "sha256": sha(data), "size": info.st_size})
                    finally: os.close(child)
                else: die(label + " contains unsupported entry")
        walk(fd, "")
    except OSError as exc: die(label + " unavailable: " + str(exc))
    finally: os.close(fd)
    return {"sha256": sha(canonical(entries)), "entries": entries}
def tuple_ok(value): return isinstance(value, dict) and set(value) == set(TUPLE) and all(hex64(value[k]) if k.endswith("Digest") else isinstance(value[k], str) and len(value[k]) == 40 and set(value[k]) <= HEX for k in TUPLE)
def command(rootfd, ref, expected, tuple_):
    raw = artifact(rootfd, ref, expected + " command record")
    if raw != canonical(parse(raw, expected + " command record")) + b"\n": die(expected + " command record is not canonical JSON")
    value = parse(raw, expected + " command record")
    exact(value, ("schemaVersion", "kind", "label", "sourceTuple", "argv", "cwd", "exitCode", "startedAt", "finishedAt", "stdout", "stderr", "observations"), expected + " command record")
    if (value["schemaVersion"] != 1 or value["kind"] != "photonport.sealed-command-record.v1"
            or value["label"] != expected or value["sourceTuple"] != tuple_ or value["exitCode"] != 0
            or not isinstance(value["argv"], list) or not value["argv"] or any(not isinstance(x, str) or not x for x in value["argv"])
            or not isinstance(value["cwd"], str) or not value["cwd"]
            or not isinstance(value["startedAt"], str) or not value["startedAt"]
            or not isinstance(value["finishedAt"], str) or not value["finishedAt"]):
        die(expected + " command record is not a passing sealed command")
    artifact(rootfd, value["stdout"], expected + " stdout")
    artifact(rootfd, value["stderr"], expected + " stderr")
    return value
def manifest_paths(raw, label):
    value = parse(raw, label)
    exact(value, ("entries",), label)
    if not isinstance(value["entries"], list): die(label + " entries are invalid")
    paths = []
    for entry in value["entries"]:
        exact(entry, ("path", "sha256", "size"), label + " entry")
        paths.append(relpath(entry["path"], label + " entry"))
        if not hex64(entry["sha256"]) or not isinstance(entry["size"], int) or isinstance(entry["size"], bool) or entry["size"] < 0: die(label + " entry is invalid")
    if paths != sorted(paths) or len(paths) != len(set(paths)): die(label + " entries are not canonical")
    return paths
def reject_build_artifacts(rootfd):
    def walk(fd, prefix):
        for name in os.listdir(fd):
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            path = prefix + name
            if name.endswith((".xcodeproj", ".app")): die("not_run request has stale generated or bundle output: " + path)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
                try: walk(child, path + "/")
                finally: os.close(child)
            elif not stat.S_ISREG(info.st_mode): die("not_run evidence contains unsupported entry")
    fd = os.dup(rootfd)
    try: walk(fd, "")
    finally: os.close(fd)
def git(root, args):
    result = subprocess.run(["git", "-C", str(root), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode: die("source tuple query failed for " + str(root))
    return result.stdout.decode("ascii", "strict").strip()
def roots_ok(values, tuple_):
    exact(values, IDS, "source roots")
    for ident in IDS:
        root = Path(values[ident]).resolve()
        if root.is_symlink() or not root.is_dir() or git(root, ["rev-parse", "HEAD"]) != tuple_[ident + "Commit"]: die(ident + " root is not exact tuple")
        clean = subprocess.run(["git", "-C", str(root), "diff-index", "--quiet", "HEAD", "--"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        unstaged = subprocess.run(["git", "-C", str(root), "diff-files", "--quiet"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        untracked = subprocess.run(["git", "-C", str(root), "ls-files", "--others", "--exclude-standard"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if clean.returncode or unstaged.returncode or untracked.stdout: die(ident + " root is dirty")
    return Path(values["ios"]).resolve()
def main():
    p = argparse.ArgumentParser(); p.add_argument("--evidence-root", required=True); p.add_argument("--request", default="r01-fresh-build-request.json"); p.add_argument("--result", default="r01-fresh-build-result.json"); a = p.parse_args()
    rootfd = open_root(a.evidence_root); request_raw = read_at(rootfd, a.request, "request"); request = parse(request_raw, "request")
    exact_keys = {"schemaVersion", "kind", "sourceTuple", "sourceRoots", "commandRecords"}
    not_run_keys = {"schemaVersion", "kind", "sourceTuple", "sourceRoots", "result"}
    if set(request) == not_run_keys:
        if request["schemaVersion"] != 1 or request["kind"] != "photonport.r01-fresh-build-request.v1" or request["result"] != "not_run" or not tuple_ok(request["sourceTuple"]): die("not_run request contract is invalid")
        ios_root = roots_ok(request["sourceRoots"], request["sourceTuple"])
        reject_build_artifacts(rootfd)
        sourcefd = open_root(ios_root)
        try: reject_build_artifacts(sourcefd)
        finally: os.close(sourcefd)
        result = {"schemaVersion": 1, "kind": "photonport.r01-fresh-build-result.v1", "result": "not_run", "requestSha256": sha(request_raw), "sourceTuple": request["sourceTuple"]}
        out = canonical(result) + b"\n"; parts = Path(relpath(a.result, "result")).parts
        fd = os.dup(rootfd)
        try:
            for part in parts[:-1]:
                fd2 = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd); os.close(fd); fd = fd2
            leaf = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=fd)
            try: os.write(leaf, out); os.fsync(leaf)
            finally: os.close(leaf)
        except FileExistsError: die("refusing to overwrite result")
        finally: os.close(fd); os.close(rootfd)
        return
    if set(request) != exact_keys or request["schemaVersion"] != 1 or request["kind"] != "photonport.r01-fresh-build-request.v1" or not tuple_ok(request["sourceTuple"]): die("request contract is invalid")
    exact(request["commandRecords"], ("before", "generation", "debugBuild", "releaseBuild"), "commandRecords")
    ios_root = roots_ok(request["sourceRoots"], request["sourceTuple"])
    records = {name: command(rootfd, request["commandRecords"][key], name, request["sourceTuple"]) for key, name in (("before", "before"), ("generation", "generation"), ("debugBuild", "debugBuild"), ("releaseBuild", "releaseBuild"))}
    before, generation, debug, release = (records[k] for k in ("before", "generation", "debugBuild", "releaseBuild"))
    exact(before["observations"], ("generatedProjectPath", "generatedProjectAbsent", "sourceManifest"), "before observations")
    project = relpath(before["observations"]["generatedProjectPath"], "generated project")
    if before["observations"]["generatedProjectAbsent"] is not True: die("before record does not observe generated project absent")
    before_manifest = artifact(rootfd, before["observations"]["sourceManifest"], "before manifest")
    before_paths = manifest_paths(before_manifest, "before manifest")
    if any(path == project or path.startswith(project + "/") for path in before_paths): die("before manifest proves generated project was present")
    if Path(generation["argv"][0]).name not in ("xcodegen", "XcodeGen"): die("generation was not an observed generator command")
    exact(generation["observations"], ("generatedProjectPath", "generatedProject", "sourceManifest"), "generation observations")
    if generation["observations"]["generatedProjectPath"] != project: die("generation project path differs")
    generated = tree(rootfd, project, "generated project")
    exact(generation["observations"]["generatedProject"], ("sha256", "entries"), "generated project observation")
    if generation["observations"]["generatedProject"] != generated: die("generated project digest mismatch")
    source_manifest = artifact(rootfd, generation["observations"]["sourceManifest"], "generation source manifest")
    if source_manifest != before_manifest: die("source changed between before and generation")
    tracked = subprocess.run(["git", "-C", str(ios_root), "ls-files", "--error-unmatch", "--", project], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if tracked.returncode == 0: die("generated project is a tracked fixture")
    bundle_results = {}
    for label, record in (("debug", debug), ("release", release)):
        if Path(record["argv"][0]).name != "xcodebuild" or label.capitalize() not in record["argv"]: die(label + " was not an observed xcodebuild configuration")
        exact(record["observations"], ("generatedProject", "sourceManifest", "bundlePath", "bundleIdentity"), label + " observations")
        if record["observations"]["generatedProject"] != generation["observations"]["generatedProject"] or artifact(rootfd, record["observations"]["sourceManifest"], label + " source manifest") != source_manifest: die(label + " is not bound to generation source")
        actual = tree(rootfd, record["observations"]["bundlePath"], label + " bundle")
        info_raw = read_at(rootfd, relpath(record["observations"]["bundlePath"], label + " bundle") + "/Info.plist", label + " Info.plist")
        try: info = plistlib.loads(info_raw)
        except Exception as exc: die(label + " Info.plist malformed: " + str(exc))
        executable = info.get("CFBundleExecutable")
        if not isinstance(executable, str) or not executable: die(label + " bundle has no executable identity")
        exe_raw = read_at(rootfd, record["observations"]["bundlePath"] + "/" + executable, label + " executable")
        identity = {"bundleSha256": actual["sha256"], "bundleIdentifier": info.get("CFBundleIdentifier"), "bundleVersion": info.get("CFBundleShortVersionString"), "buildVersion": info.get("CFBundleVersion"), "executableSha256": sha(exe_raw)}
        if record["observations"]["bundleIdentity"] != identity or not all(isinstance(identity[k], str) and identity[k] for k in ("bundleIdentifier", "bundleVersion", "buildVersion")): die(label + " actual bundle identity mismatch")
        bundle_results[label] = identity
    result = {"schemaVersion": 1, "kind": "photonport.r01-fresh-build-result.v1", "result": "passed", "requestSha256": sha(request_raw), "sourceTuple": request["sourceTuple"], "commandRecords": request["commandRecords"], "generatedProject": generation["observations"]["generatedProject"], "bundles": bundle_results}
    out = canonical(result) + b"\n"; parts = Path(relpath(a.result, "result")).parts
    fd = os.dup(rootfd)
    try:
        for part in parts[:-1]:
            fd2 = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd); os.close(fd); fd = fd2
        leaf = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=fd)
        try: os.write(leaf, out); os.fsync(leaf)
        finally: os.close(leaf)
    except FileExistsError: die("refusing to overwrite result")
    finally: os.close(fd); os.close(rootfd)
if __name__ == "__main__": main()
