"""Verify the explicitly selected public baseline after its source FD is admitted."""
import hashlib
import json
import os
import pathlib
import re
import stat

SCHEMA = "release-studio.shellx-drive-linux-public-baseline/v1"
EXPORT_SCHEMA = "release-studio.shellx-drive-linux-public-baseline-export/v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BASE_IMAGE = "ubuntu@sha256:b1066385161d28ddf6bc7e7b28a9170eec11484c821d1a5150d176cbde41d7f7"
ETC = ["alternatives", "fonts", "ld.so.cache", "ld.so.conf", "ld.so.conf.d", "os-release", "ssl"]
SELECTION = {"etc": ETC, "hardlinks": "single-link-copies", "roots": ["usr", "etc"], "symlinks": "dereference-in-image-no-host-fallback"}
METADATA = {"packageInventory": "package-inventory.tsv", "exportReceipt": "public-baseline-export-receipt.json"}
LIMIT = 16 * 1024 * 1024


def fail(message):
    raise SystemExit(f"FAIL: public baseline {message}")


def metadata(value, root, role):
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "size", "dev", "inode", "uid", "mode"}:
        fail(f"{role} identity shape is invalid")
    path = pathlib.Path(value["path"])
    if str(path) != str(pathlib.Path(root["path"]).parent / METADATA[role]) or not path.is_absolute() or str(path.resolve()) != str(path):
        fail(f"{role} escaped its fixed physical sibling role")
    before = path.lstat()
    expected = (value["dev"], value["inode"], value["uid"], value["mode"], value["size"])
    observed = (str(before.st_dev), str(before.st_ino), before.st_uid, f"{stat.S_IMODE(before.st_mode):04o}", before.st_size)
    if (observed != expected or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
            before.st_uid != root["uid"] or stat.S_IMODE(before.st_mode) & 0o7222 or not 0 < before.st_size <= LIMIT or
            not isinstance(value["sha256"], str) or not SHA256.fullmatch(value["sha256"])):
        fail(f"{role} identity changed")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    signature = lambda item: (item.st_dev, item.st_ino, item.st_uid, item.st_mode, item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    try:
        if signature(before) != signature(os.fstat(fd)):
            fail(f"{role} changed before reading")
        chunks, offset = [], 0
        while offset < before.st_size:
            chunk = os.pread(fd, min(1024 * 1024, before.st_size - offset), offset)
            if not chunk:
                fail(f"{role} ended while reading")
            chunks.append(chunk)
            offset += len(chunk)
        content = b"".join(chunks)
        if signature(before) != signature(os.fstat(fd)) or signature(before) != signature(path.lstat()) or hashlib.sha256(content).hexdigest() != value["sha256"]:
            fail(f"{role} changed while reading")
        return content
    finally:
        os.close(fd)


def verify_public_baseline(value, dependency_root, verify_directory):
    if not isinstance(value, dict) or set(value) != {"schema", "root", "baseImage", "imageDigest", "compilerRuntimeMountPath", "packageInventory", "exportReceipt"}:
        fail("record shape is invalid")
    if value["schema"] != SCHEMA or value["baseImage"] != BASE_IMAGE or not isinstance(value["imageDigest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["imageDigest"]):
        fail("image identity is invalid")
    if value["compilerRuntimeMountPath"] not in {"/usr/lib/gcc/x86_64-linux-gnu/11", "/usr/libexec/gcc/x86_64-linux-gnu/13"}:
        fail("compiler prefix is invalid")
    if value["root"] != dependency_root:
        fail("dependency root differs from selected identity")
    verify_directory(value["root"], "public baseline root", immutable=True)
    root = pathlib.Path(value["root"]["path"])
    if sorted(item.name for item in root.iterdir()) != ["etc", "usr"] or any(item.name not in ETC for item in (root / "etc").iterdir()):
        fail("tree escaped its positive runtime selection")
    inventory = metadata(value["packageInventory"], value["root"], "packageInventory")
    receipt = metadata(value["exportReceipt"], value["root"], "exportReceipt")
    try:
        text = inventory.decode("utf-8")
        rows = text[:-1].split("\n")
        packages = set()
        if not text.endswith("\n") or "\r" in text or "\0" in text or len(rows) > 20_000:
            fail("package inventory format is invalid")
        for row in rows:
            fields = row.split("\t")
            if len(fields) != 3 or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::amd64)?", fields[0]) or not re.fullmatch(r"[0-9A-Za-z.+:~_-]+", fields[1]) or fields[2] not in {"amd64", "all"}:
                fail("package inventory row is invalid")
            name = fields[0].removesuffix(":amd64")
            if name in packages:
                fail("package inventory contains duplicates")
            packages.add(name)
        if not {"libc6", "libgtk-3-0", "libwebkit2gtk-4.1-0", "gcc-11"} <= packages:
            fail("package inventory lacks the runtime/compiler closure")
        expected = {"schema": EXPORT_SCHEMA, "baseImage": value["baseImage"], "imageDigest": value["imageDigest"], "compilerRuntimeMountPath": value["compilerRuntimeMountPath"],
                    "packageInventorySha256": value["packageInventory"]["sha256"], "treeDigest": value["root"]["treeDigest"], "selection": SELECTION}
        if json.loads(receipt) != expected:
            fail("export receipt differs from the admitted image, tree, inventory, or recipe")
    except (UnicodeError, ValueError) as error:
        fail(f"metadata is invalid: {error}")
