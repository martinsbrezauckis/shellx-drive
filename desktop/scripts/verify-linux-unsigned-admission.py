#!/usr/bin/env python3
"""Validate the signing-free Linux unsigned-build admission on held descriptors."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import stat

SCHEMA = "release-studio.shellx-drive-unsigned-build-admission/v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OID = re.compile(r"^[0-9a-f]{40}$")
SOURCE_FDS = {
    "tauri-linux-config": (111, "desktop/src-tauri/tauri.linux.conf.json"),
    "write-linux-unsigned-handoff": (115, "desktop/scripts/write-linux-unsigned-handoff.mjs"),
}
PARSER_FD = 116
PARSER_PATH = "desktop/scripts/verify-linux-unsigned-admission.py"
WORKER_PATH = "desktop/scripts/linux-unsigned-build.sh"


def fail(message):
    raise SystemExit(f"FAIL: {message}")


def digest_fd(fd, size):
    value = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(fd, min(1024 * 1024, size - offset), offset)
        if not chunk:
            break
        value.update(chunk)
        offset += len(chunk)
    return value.hexdigest()


def identity(fd, expected, label, executable=False, descriptor_fd=None):
    expected_keys = {"path", "sha256", "dev", "inode", "uid", "mode"}
    if descriptor_fd is not None:
        expected_keys.add("fd")
        if expected.get("fd") != descriptor_fd:
            fail(f"{label} admission descriptor number is invalid")
    if set(expected) != expected_keys:
        fail(f"{label} admission identity shape is invalid")
    observed = os.fstat(fd)
    actual = (str(observed.st_dev), str(observed.st_ino), observed.st_uid, f"{stat.S_IMODE(observed.st_mode):04o}")
    wanted = (expected["dev"], expected["inode"], expected["uid"], expected["mode"])
    if (not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1 or actual != wanted or
            (executable and not observed.st_mode & 0o111) or stat.S_IMODE(observed.st_mode) & 0o022 or
            not SHA256.fullmatch(expected["sha256"]) or digest_fd(fd, observed.st_size) != expected["sha256"]):
        fail(f"{label} descriptor identity changed")


def stage_digest(root):
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    root_fd = os.open(root, directory_flags)
    root_meta = os.fstat(root_fd)
    if stat.S_IMODE(root_meta.st_mode) != 0o700:
        os.close(root_fd)
        fail("unsigned admission stage root mode changed")
    records = []

    def walk(directory_fd, prefix=""):
        for name in sorted((entry.name for entry in os.scandir(directory_fd)), key=os.fsencode):
            relative = f"{prefix}/{name}" if prefix else name
            entry_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if hasattr(os, "O_CLOEXEC"):
                entry_flags |= os.O_CLOEXEC
            fd = os.open(name, entry_flags, dir_fd=directory_fd)
            before = os.fstat(fd)
            mode = stat.S_IMODE(before.st_mode)
            if before.st_uid != root_meta.st_uid or mode & 0o022:
                os.close(fd)
                fail("unsigned admission stage identity is unsafe")
            if stat.S_ISDIR(before.st_mode):
                walk(fd, relative)
                os.close(fd)
                continue
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                os.close(fd)
                fail("unsigned admission stage contains an unsupported entry")
            git_digest = hashlib.sha1()
            git_digest.update(f"blob {before.st_size}\0".encode())
            content_digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    os.close(fd)
                    fail("unsigned admission stage file ended while hashing")
                git_digest.update(chunk)
                content_digest.update(chunk)
                remaining -= len(chunk)
            after = os.fstat(fd)
            os.close(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                fail("unsigned admission stage changed while hashing")
            records.append((relative, f"{relative}\0{'100755' if before.st_mode & 0o111 else '100644'}\0{git_digest.hexdigest()}\0{content_digest.hexdigest()}\0{before.st_size}\n".encode()))

    walk(root_fd)
    os.close(root_fd)
    value = hashlib.sha256()
    for _, record in sorted(records, key=lambda item: item[0].encode()):
        value.update(record)
    return value.hexdigest()


def immutable_directory_tree(path, root, label, immutable=False):
    content = hashlib.sha256()
    descriptors = hashlib.sha256()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    root_fd = os.open(path, directory_flags)
    try:
        root_before = os.fstat(root_fd)
        if (root_before.st_dev, root_before.st_ino, root_before.st_uid, stat.S_IMODE(root_before.st_mode)) != (
                root.st_dev, root.st_ino, root.st_uid, stat.S_IMODE(root.st_mode)):
            fail(f"{label} root changed while reopening")

        def walk(directory_fd, prefix=""):
            names = sorted((entry.name for entry in os.scandir(directory_fd)), key=os.fsencode)
            for name in names:
                if not name or "/" in name or "\0" in name or "\r" in name or "\n" in name:
                    fail(f"{label} contains an unsafe entry name")
                relative = f"{prefix}/{name}" if prefix else name
                observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                mode = stat.S_IMODE(observed.st_mode)
                if observed.st_uid != root.st_uid or mode & (0o7222 if immutable else 0o022):
                    fail(f"{label} entry {relative} has unsafe owner/mode")
                entry_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if hasattr(os, "O_CLOEXEC"):
                    entry_flags |= os.O_CLOEXEC
                fd = os.open(name, entry_flags, dir_fd=directory_fd)
                try:
                    held = os.fstat(fd)
                    if (held.st_dev, held.st_ino, held.st_uid, stat.S_IMODE(held.st_mode)) != (
                            observed.st_dev, observed.st_ino, observed.st_uid, mode):
                        fail(f"{label} entry {relative} changed while opening")
                    if stat.S_ISDIR(held.st_mode):
                        content.update(f"D\0{relative}\0{mode:o}\n".encode())
                        descriptors.update(f"D\0{relative}\0{held.st_dev}\0{held.st_ino}\0{mode:o}\n".encode())
                        walk(fd, relative)
                    elif stat.S_ISREG(held.st_mode):
                        if held.st_nlink != 1:
                            fail(f"{label} file {relative} must be a single-link private copy")
                        digest = hashlib.sha256()
                        remaining = held.st_size
                        offset = 0
                        while remaining:
                            chunk = os.pread(fd, min(1024 * 1024, remaining), offset)
                            if not chunk:
                                fail(f"{label} file {relative} ended while hashing")
                            digest.update(chunk)
                            offset += len(chunk)
                            remaining -= len(chunk)
                        after = os.fstat(fd)
                        if (held.st_dev, held.st_ino, held.st_uid, held.st_mode, held.st_size, held.st_mtime_ns, held.st_ctime_ns) != (
                                after.st_dev, after.st_ino, after.st_uid, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                            fail(f"{label} file {relative} changed while hashing")
                        content.update(f"F\0{relative}\0{mode:o}\0{held.st_size}\0{digest.hexdigest()}\n".encode())
                        descriptors.update(f"F\0{relative}\0{held.st_dev}\0{held.st_ino}\0{mode:o}\0{held.st_size}\n".encode())
                    else:
                        fail(f"{label} contains unsupported entry {relative}")
                finally:
                    os.close(fd)

        walk(root_fd)
        root_after = os.fstat(root_fd)
        if (root_before.st_dev, root_before.st_ino, root_before.st_uid, root_before.st_mode, root_before.st_mtime_ns, root_before.st_ctime_ns) != (
                root_after.st_dev, root_after.st_ino, root_after.st_uid, root_after.st_mode, root_after.st_mtime_ns, root_after.st_ctime_ns):
            fail(f"{label} root changed while hashing")
        return content.hexdigest(), descriptors.hexdigest()
    finally:
        os.close(root_fd)


def directory_identity(value, label, immutable=False):
    if set(value) != {"path", "treeDigest", "descriptorDigest", "dev", "inode", "uid", "mode"}:
        fail(f"{label} identity shape is invalid")
    path = pathlib.Path(value["path"])
    if not path.is_absolute() or str(path.resolve()) != str(path) or path.is_symlink() or not path.is_dir():
        fail(f"{label} path is invalid")
    observed = path.stat()
    actual = (str(observed.st_dev), str(observed.st_ino), observed.st_uid, f"{stat.S_IMODE(observed.st_mode):04o}")
    wanted = (value["dev"], value["inode"], value["uid"], value["mode"])
    if actual != wanted or (stat.S_IMODE(observed.st_mode) & 0o7222 if immutable else value["mode"] != "0700") or not SHA256.fullmatch(value["treeDigest"]) or not SHA256.fullmatch(value["descriptorDigest"]):
        fail(f"{label} identity changed")
    tree_digest, descriptor_digest = immutable_directory_tree(str(path), observed, label, immutable)
    if tree_digest != value["treeDigest"] or descriptor_digest != value["descriptorDigest"]:
        fail(f"{label} contents changed")


def parse_admission():
    metadata = os.fstat(3)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
        fail("unsigned admission fd must be a private single-link regular file")
    try:
        os.lseek(3, 0, os.SEEK_SET)
        return json.loads(os.read(3, metadata.st_size).decode("utf-8"))
    except Exception as error:
        fail(f"unsigned admission is not valid JSON: {error}")


def reject_signing_environment():
    forbidden = {"GNUPGHOME", "GPG_AGENT_INFO", "SSH_AUTH_SOCK", "TAURI_SIGNING_PRIVATE_KEY", "TAURI_SIGNING_PRIVATE_KEY_PASSWORD", "TAURI_PRIVATE_KEY", "TAURI_PRIVATE_KEY_PASSWORD", "CSC_LINK", "CSC_KEY_PASSWORD"}
    for name in os.environ:
        if name in forbidden or name.startswith(("GNUPG", "GPG_", "TAURI_SIGNING_", "TAURI_PRIVATE_", "CSC_", "NOTARY_", "APPLE_", "DEVELOPER_ID_")):
            fail(f"signing environment is forbidden: {name}")


parser = argparse.ArgumentParser()
parser.add_argument("action", choices=("verify-unsigned-admission",))
parser.add_argument("--admission", required=True)
parser.add_argument("--stage-root", required=True)
parser.add_argument("--output-root", required=True)
parser.add_argument("--format", choices=("shell",), required=True)
args = parser.parse_args()
if args.admission != "/dev/fd/3" or args.format != "shell":
    fail("unsigned admission verification arguments are incomplete")
reject_signing_environment()
data = parse_admission()
if set(data) != {"builder", "candidateRoot", "platform", "project", "releaseStudio", "runtime", "schema", "source", "tools", "version"}:
    fail("unsigned admission has unexpected or missing fields")
if data.get("schema") != SCHEMA or data.get("project") != "shellx-drive" or data.get("platform") != "linux-x86_64" or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", data.get("version", "")):
    fail("unsigned admission identity is invalid")
source = data.get("source", {})
if set(source) != {"commit", "fullStageDigest", "tree"} or not OID.fullmatch(source["commit"]) or not OID.fullmatch(source["tree"]) or not SHA256.fullmatch(source["fullStageDigest"]):
    fail("unsigned admission source is invalid")
builder = data.get("builder", {})
if set(builder) != {"hostId", "toolchainManifestSha256"} or builder["hostId"] != "linux-native" or not SHA256.fullmatch(builder["toolchainManifestSha256"]):
    fail("unsigned admission builder is invalid")
release = data.get("releaseStudio", {})
if set(release) != {"collectorSha256", "commit", "tree"} or not SHA256.fullmatch(release["collectorSha256"]) or not OID.fullmatch(release["commit"]) or not OID.fullmatch(release["tree"]):
    fail("unsigned build admission controller identity is invalid")
output = pathlib.Path(data.get("candidateRoot", ""))
if not output.is_absolute() or str(output) != args.output_root or output.exists() or output.parent.name == "":
    fail("unsigned admission output root is invalid or not fresh")
stage = pathlib.Path(args.stage_root)
if not stage.is_absolute() or stage.is_symlink() or not stage.is_dir() or stat.S_IMODE(stage.stat().st_mode) != 0o700:
    fail("unsigned admission stage root is invalid")
if stage_digest(stage) != source["fullStageDigest"]:
    fail("unsigned admission full-stage digest changed")
runtime = data.get("runtime", {})
baseline_selected = "publicBaseline" in runtime
if set(runtime) != {"admissionParser", "dependencyRoots", "sourceDescriptors", "toolDescriptors", "toolPath", "worker"} | ({"publicBaseline"} if baseline_selected else set()):
    fail("unsigned admission runtime has unexpected or missing fields")
if runtime["worker"].get("path") != str(stage / WORKER_PATH):
    fail("unsigned admission worker path drifted")
identity(4, runtime["worker"], "unsigned worker", executable=True)
if runtime["admissionParser"].get("path") != str(stage / PARSER_PATH):
    fail("unsigned admission parser path drifted")
identity(PARSER_FD, runtime["admissionParser"], "unsigned admission parser", descriptor_fd=PARSER_FD)
if baseline_selected:
    SOURCE_FDS["verify-linux-public-baseline"] = (117, "desktop/scripts/verify-linux-public-baseline.py")
if set(runtime["sourceDescriptors"]) != set(SOURCE_FDS):
    fail("unsigned admission source descriptors are incomplete")
for name, (fd, relative) in SOURCE_FDS.items():
    descriptor = runtime["sourceDescriptors"][name]
    if descriptor.get("fd") != fd or descriptor.get("path") != str(stage / relative):
        fail(f"unsigned admission source descriptor drifted: {name}")
    identity(fd, descriptor, f"unsigned source descriptor {name}", descriptor_fd=fd)
if runtime["toolPath"] != "/tools" or os.environ.get("PATH") != runtime["toolPath"]:
    fail("unsigned admission PATH escaped its admitted tool root")
dependencies = runtime["dependencyRoots"]
if set(dependencies) != {"cargoHome", "compilerRuntime", "rustupHome"} | ({"publicBaseline"} if baseline_selected else set()):
    fail("unsigned admission dependency roots are incomplete")
for name, environment in (("cargoHome", "CARGO_HOME"), ("rustupHome", "RUSTUP_HOME")):
    directory_identity(dependencies[name], f"unsigned dependency root {name}")
    if os.environ.get(environment) != dependencies[name]["path"]:
        fail(f"unsigned admission {environment} escaped its admitted dependency root")
directory_identity(dependencies["compilerRuntime"], "unsigned compiler runtime")
if baseline_selected:
    helper = runtime["sourceDescriptors"]["verify-linux-public-baseline"]
    namespace = {"__name__": "held_public_baseline"}
    exec(compile(os.pread(117, os.fstat(117).st_size, 0), helper["path"], "exec"), namespace)
    namespace["verify_public_baseline"](runtime["publicBaseline"], dependencies["publicBaseline"], directory_identity)
tools = data.get("tools", {})
descriptors = runtime["toolDescriptors"]
if not isinstance(tools, dict) or not isinstance(descriptors, dict) or set(tools) != set(descriptors) or not tools:
    fail("unsigned admission tools are incomplete")
for name, expected in tools.items():
    fd = descriptors[name]
    if not isinstance(fd, int) or fd < 10:
        fail(f"unsigned admission tool descriptor is invalid: {name}")
    identity(fd, expected, f"unsigned tool {name}", executable=True)
print("SHELLX_DRIVE_LINUX_UNSIGNED_ADMISSION_OK")
