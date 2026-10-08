"""Bounded filesystem, canonical JSON, and OpenPGP primitives for Linux trust."""
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import unicodedata

MAX_DOCUMENT = 4 * 1024 * 1024
MAX_SIGNATURE = 4 * 1024 * 1024
MAX_KEYRING = 32 * 1024 * 1024
SAFE_INTEGER = 9007199254740991
FINGERPRINT = re.compile(r"^[A-F0-9]{40,64}$")
GPG_FAILURE_STATUSES = frozenset((b"BADSIG", b"ERRSIG", b"EXPSIG", b"EXPKEYSIG", b"FAILURE", b"NODATA", b"NO_PUBKEY", b"REVKEYSIG"))


class VerificationError(Exception):
    pass


def fail(message):
    raise VerificationError(message)


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        fail(f"{label} has unexpected or missing fields")


def safe_leaf(value, label):
    if not isinstance(value, str) or pathlib.PurePath(value).name != value or value in ("", ".", "..") or any(char in value for char in "\0\r\n"):
        fail(f"{label} is not a safe file name")


def require_pattern(value, pattern, label):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        fail(f"{label} is malformed")


def require_integer(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= SAFE_INTEGER:
        fail(f"{label} must be a non-negative safe integer")


def canonical(value, label="canonical JSON"):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if not -SAFE_INTEGER <= value <= SAFE_INTEGER:
            fail(f"{label} integer is unsafe")
        return str(value)
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value or any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            fail(f"{label} text is not NFC")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonical(item, label) for item in value) + "]"
    if isinstance(value, dict):
        ordered = sorted(value.items(), key=lambda item: item[0].encode("utf-8"))
        return "{" + ",".join(f"{canonical(key, label)}:{canonical(item, label)}" for key, item in ordered) + "}"
    fail(f"{label} contains unsupported data")


def parse_json(body, label, require_canonical=False):
    def pairs(items):
        result = {}
        for key, value in items:
            if not isinstance(key, str) or unicodedata.normalize("NFC", key) != key or key in result:
                fail(f"{label} has duplicate or non-NFC keys")
            result[key] = value
        return result

    def integer(token):
        if token == "-0":
            fail(f"{label} contains negative zero")
        value = int(token)
        if not -SAFE_INTEGER <= value <= SAFE_INTEGER:
            fail(f"{label} integer is unsafe")
        return value

    try:
        text = body.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=lambda _: fail(f"{label} permits integers only"),
            parse_constant=lambda _: fail(f"{label} permits integers only"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        fail(f"{label} is invalid JSON: {error}")
    if require_canonical and body != f"{canonical(value, label)}\n".encode("utf-8"):
        fail(f"{label} is not canonical JSON")
    return value


def normalized(path, label, directory=False):
    value = os.path.abspath(path)
    if path != value or (path != "/" and path.endswith(os.sep)):
        fail(f"{label} must be a normalized absolute path")
    try:
        observed = os.lstat(path)
    except OSError as error:
        fail(f"{label} is unavailable: {error}")
    if stat.S_ISLNK(observed.st_mode) or os.path.realpath(path) != path:
        fail(f"{label} must not resolve through a symlink")
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(observed.st_mode):
        fail(f"{label} has the wrong file type")
    return pathlib.Path(path)


def stable_bytes(path, label, limit):
    target = normalized(path, label)
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size > limit:
            fail(f"{label} has unsafe mode, links, or size")
        chunks = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(fd)
        current = os.lstat(target)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if tuple(getattr(before, key) for key in fields) != tuple(getattr(after, key) for key in fields) or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino):
            fail(f"{label} changed while read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def stable_hash(path, label):
    target = normalized(path, label)
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size > SAFE_INTEGER:
            fail(f"{label} is not safely attestable")
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(fd)
        current = os.lstat(target)
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if tuple(getattr(before, key) for key in fields) != tuple(getattr(after, key) for key in fields) or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino):
            fail(f"{label} changed while hashed")
        return {"sha256": digest.hexdigest(), "size": after.st_size, "mode": f"{stat.S_IMODE(after.st_mode):04o}"}
    finally:
        os.close(fd)


def verify_signature(payload, signature, keyring, fingerprint, label):
    with tempfile.TemporaryDirectory(prefix="shellx-drive-linux-trust-") as temporary:
        os.chmod(temporary, 0o700)
        paths = []
        for name, body in (("payload", payload), ("signature", signature), ("keyring", keyring)):
            path = os.path.join(temporary, name)
            with open(path, "xb") as output:
                os.chmod(path, 0o600)
                output.write(body)
            paths.append(path)
        result = subprocess.run(
            ["/usr/bin/gpgv", "--status-fd=1", "--keyring", paths[2], paths[1], paths[0]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            check=False,
        )
    if result.returncode:
        fail(f"{label} signature did not verify")
    statuses = [line.split() for line in result.stdout.splitlines() if line.startswith(b"[GNUPG:] ")]
    valid = [fields for fields in statuses if len(fields) >= 2 and fields[1] == b"VALIDSIG"]
    if any(len(fields) >= 2 and fields[1] in GPG_FAILURE_STATUSES for fields in statuses) or len(valid) != 1:
        fail(f"{label} signature did not bind the one pinned fingerprint")
    fields = valid[0]
    if len(fields) != 12:
        fail(f"{label} signature did not bind the one pinned fingerprint")
    try:
        signing_fingerprint = fields[2].decode("ascii", "strict")
        primary_fingerprint = fields[11].decode("ascii", "strict")
    except UnicodeDecodeError:
        fail(f"{label} signature did not bind the one pinned fingerprint")
    if not FINGERPRINT.fullmatch(signing_fingerprint) or not FINGERPRINT.fullmatch(primary_fingerprint) or primary_fingerprint != fingerprint:
        fail(f"{label} signature did not bind the one pinned fingerprint")


def receipt_output(path, value):
    parent = normalized(os.path.dirname(path), "receipt parent", True)
    meta = parent.stat()
    if meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) & 0o077 or os.path.lexists(path):
        fail("receipt output must be fresh below a private caller-owned directory")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(f"{canonical(value)}\n".encode("utf-8"))
