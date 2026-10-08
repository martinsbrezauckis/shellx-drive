"""Physical macOS candidate and raw-evidence identity checks."""
import hashlib
import os
import stat
import unicodedata

from macos_terminal_attestation_common import EVIDENCE_FILES, SAFE_INTEGER, fail, safe_file


def normalized_absolute(path, label):
    if not os.path.isabs(path) or os.path.normpath(path) != path or path.endswith(os.sep):
        fail(f"{label} must be a normalized absolute path")
    return path


def physical(path, label, kind):
    normalized_absolute(path, label)
    try:
        observed = os.lstat(path)
    except OSError as error:
        fail(f"{label} is unavailable: {error}")
    if stat.S_ISLNK(observed.st_mode) or os.path.realpath(path) != path:
        fail(f"{label} must not resolve through a symlink")
    if kind == "file" and not stat.S_ISREG(observed.st_mode):
        fail(f"{label} must be a regular file")
    if kind == "directory" and not stat.S_ISDIR(observed.st_mode):
        fail(f"{label} must be a directory")
    return observed


def stable_file(path, label, limit=64 * 1024 * 1024):
    physical(path, label, "file")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        fail(f"{label} cannot be opened safely: {error}")
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"{label} must be a single-link regular file")
        if before.st_mode & 0o022:
            fail(f"{label} must not be group/world writable")
        if before.st_size > limit:
            fail(f"{label} exceeds the input limit")
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(fd)
        current = os.lstat(path)
        keys = ("st_dev", "st_ino", "st_uid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if tuple(getattr(before, key) for key in keys) != tuple(getattr(after, key) for key in keys) or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino):
            fail(f"{label} changed while it was read")
        return b"".join(chunks), after
    finally:
        os.close(fd)


def hash_file(path, label):
    physical(path, label, "file")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        fail(f"{label} cannot be opened safely: {error}")
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > SAFE_INTEGER:
            fail(f"{label} must be a safely attestable single-link regular file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        current = os.lstat(path)
        keys = ("st_dev", "st_ino", "st_uid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if tuple(getattr(before, key) for key in keys) != tuple(getattr(after, key) for key in keys) or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino):
            fail(f"{label} changed while it was hashed")
        return {"sha256": digest.hexdigest(), "size": after.st_size}
    finally:
        os.close(fd)


def require_candidate_file(directory, name, expected, label):
    safe_file(name, f"{label}.name")
    physical(directory, f"{label} parent", "directory")
    observed = hash_file(os.path.join(directory, name), label)
    if observed["sha256"] != expected["sha256"]:
        fail(f"{label} bytes do not match the attestation hash")
    if "size" in expected and observed["size"] != expected["size"]:
        fail(f"{label} size does not match the attestation")


def _mode4(mode):
    return f"{mode & 0o7777:04o}"


def app_tree_digest(app_path):
    root = physical(app_path, "macOS app bundle", "directory")
    physical_root = os.path.realpath(app_path)
    records, names_seen = [f"D\0.\0{_mode4(root.st_mode)}\n"], {"."}

    def walk(directory, parent=""):
        entries = []
        for raw in os.listdir(directory):
            normalized = unicodedata.normalize("NFC", raw)
            if not raw or normalized != raw or "\0" in raw or "\r" in raw or "\n" in raw:
                fail("app entry must be a canonical safe Unicode name")
            entries.append((raw, normalized))
        entries.sort(key=lambda entry: entry[1].encode("utf-8"))
        for raw, normalized in entries:
            relative = f"{parent}/{normalized}" if parent else normalized
            if relative in names_seen:
                fail(f"app tree has NFC-normalized path collision at {relative}")
            names_seen.add(relative)
            absolute, observed = os.path.join(directory, raw), os.lstat(os.path.join(directory, raw))
            if stat.S_ISDIR(observed.st_mode):
                if not os.path.realpath(absolute).startswith(f"{physical_root}{os.sep}"):
                    fail(f"app directory {relative} escapes the bundle")
                records.append(f"D\0{relative}\0{_mode4(observed.st_mode)}\n")
                walk(absolute, relative)
            elif stat.S_ISREG(observed.st_mode):
                digest = hash_file(absolute, f"app file {relative}")
                records.append(f"F\0{relative}\0{_mode4(observed.st_mode)}\0{digest['size']}\0{digest['sha256']}\n")
            elif stat.S_ISLNK(observed.st_mode):
                target = os.readlink(absolute)
                if not target or os.path.isabs(target) or unicodedata.normalize("NFC", target) != target or any(ch in target for ch in "\0\r\n"):
                    fail(f"app symlink {relative} has a noncanonical target")
                resolved = os.path.realpath(os.path.join(os.path.dirname(absolute), target))
                if resolved != physical_root and not resolved.startswith(f"{physical_root}{os.sep}"):
                    fail(f"app symlink {relative} escapes the bundle")
                records.append(f"L\0{relative}\0{target}\n")
            else:
                fail(f"app tree contains unsupported entry {relative}")

    walk(app_path)
    after = os.lstat(app_path)
    keys = ("st_dev", "st_ino", "st_uid", "st_mode", "st_mtime_ns", "st_ctime_ns")
    if tuple(getattr(root, key) for key in keys) != tuple(getattr(after, key) for key in keys):
        fail("macOS app root changed during inspection")
    return hashlib.sha256("".join(records).encode("utf-8")).hexdigest()


def verify_app(value, app_path, label):
    app = value["artifacts"]["app"]
    if app_tree_digest(app_path) != app["treeDigest"]:
        fail(f"{label} tree bytes do not match the attestation hash")
    executable = os.path.join(app_path, *app["executableRelativePath"].split("/"))
    observed = hash_file(executable, f"{label} executable")
    if observed["sha256"] != app["executableSha256"]:
        fail(f"{label} executable bytes do not match the attestation hash")
    return {"cdHash": app["cdHash"], "executableRelativePath": app["executableRelativePath"], "executableSha256": observed["sha256"], "path": app_path, "treeDigest": app["treeDigest"]}


def verify_installed_app(value, app_path):
    normalized_absolute(app_path, "installed macOS app")
    return verify_app(value, app_path, "installed macOS app")


def verify_candidate(value, candidate_dir):
    artifacts = os.path.join(candidate_dir, "artifacts")
    physical(artifacts, "candidate artifacts directory", "directory")
    app = value["artifacts"]["app"]
    verify_app(value, os.path.join(artifacts, app["name"]), "candidate app")
    for role in ("dmg", "updaterArchive", "updaterSignature"):
        require_candidate_file(artifacts, value["artifacts"][role]["name"], value["artifacts"][role], f"candidate {role}")
    require_candidate_file(candidate_dir, value["workerObservation"]["name"], value["workerObservation"], "candidate worker observation")
    observations = os.path.join(candidate_dir, "observations")
    for key, name in EVIDENCE_FILES.items():
        require_candidate_file(candidate_dir if key == "workerComplete" else observations, name, value["rawEvidence"][key], f"candidate raw evidence {key}")
