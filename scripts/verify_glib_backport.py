#!/usr/bin/env python3
"""Verify the retained RUSTSEC-2024-0429 source backport without waiving it."""

import argparse
import hashlib
import json
import os
import re
import sys
import tomllib
from pathlib import Path


VENDOR_RELATIVE = Path("desktop/vendor/glib-0.18.5-rustsec-2024-0429")
VENDOR_WORKSPACE_RELATIVE = VENDOR_RELATIVE.relative_to("desktop").as_posix()
INVENTORY_NAME = "SHA256SUMS"
EXPECTED_VENDOR_FILES = 122
BASE_ARCHIVE_SHA256 = "233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5"
UPSTREAM_URL = "https://github.com/gtk-rs/gtk-rs-core/pull/1343"
UPSTREAM_COMMIT = "b5a4071"
SAFE_API_CORRECTIONS = {
    "src/boxed_inline.rs": (".checked_mul(std::cmp::max(t.len(), 1))",),
    "src/collections/strv.rs": ("*new_ptr = ptr::null_mut();", "*self.ptr.as_ptr() = ptr::null_mut();"),
    "src/gstring.rs": ("as *const u8, *len) };", "as *const u8, *len + 1) };"),
    "src/log.rs": ("pub fn new(key: &'a GStr, value: &'a [u8]) -> Self",),
    "src/collections/list.rs": (
        "let item = &*(&(*ptr).data as *const ffi::gpointer as *const T);",
        "self.ptr.unwrap().as_ptr(),", "ffi::g_list_copy(self.as_ptr() as *mut _)",
    ),
    "src/collections/slist.rs": (
        "let item = &*(&(*ptr).data as *const ffi::gpointer as *const T);",
        "self.ptr.unwrap().as_ptr(),", "ffi::g_slist_copy(self.as_ptr() as *mut _)",
    ),
}


class VerificationError(Exception):
    """Raised when the retained source no longer matches the reviewed backport."""


def fail(message):
    raise VerificationError(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def vendor_files(root):
    if root.is_symlink() or not root.is_dir():
        fail("vendor root must be a regular directory")
    files = {}
    for current, directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            if (current_path / name).is_symlink():
                fail(f"vendor contains a symlinked directory: {current_path / name}")
        for name in names:
            path = current_path / name
            if path.is_symlink():
                fail(f"vendor contains a symlinked file: {path}")
            if not path.is_file():
                fail(f"vendor contains a non-regular file: {path}")
            files[path.relative_to(root).as_posix()] = path
    return files


def inventory(root):
    path = root / INVENTORY_NAME
    if path.is_symlink() or not path.is_file():
        fail("vendor inventory must be a regular file")
    records = {}
    previous = ""
    for number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/].*)", line)
        if not match:
            fail(f"invalid inventory entry at line {number}")
        digest, relative = match.groups()
        parts = relative.split("/")
        if relative == INVENTORY_NAME or any(part in {"", ".", ".."} for part in parts):
            fail(f"unsafe inventory path at line {number}")
        if relative <= previous or relative in records:
            fail("inventory paths must be unique and sorted")
        previous = relative
        records[relative] = digest
    if len(records) != EXPECTED_VENDOR_FILES:
        fail(f"inventory must contain {EXPECTED_VENDOR_FILES} retained files")
    return records


def verify_file_set(expected, actual):
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    if missing or extra:
        fail(f"vendor file set changed; missing={missing}, extra={extra}")


def verify_digests(files, records):
    for relative, expected in records.items():
        actual = sha256(files[relative])
        if actual != expected:
            fail(f"vendor digest mismatch: {relative}")


def verify_pointer(source):
    required = (
        "let mut p: *mut libc::c_char = std::ptr::null_mut();",
        "                &mut p,",
    )
    if any(value not in source for value in required):
        fail("VariantStrIter must use the reviewed mutable C out-pointer")
    if "let p: *mut libc::c_char" in source or "                &p," in source:
        fail("VariantStrIter reverted the unsafe immutable out-pointer")


def load_toml(path):
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read TOML {path}: {error}")


def verify_safe_apis(vendor):
    for relative, required in SAFE_API_CORRECTIONS.items():
        source = (vendor / relative).read_text(encoding="utf-8")
        if any(value not in source for value in required):
            fail(f"safe-API correction missing: {relative}")


def verify_resolution(root, vendor):
    desktop = load_toml(root / "desktop/Cargo.toml")
    workspace = desktop.get("workspace", {})
    if workspace.get("members") != [
        "mirror-core", "src-tauri", "updater-verifier", VENDOR_WORKSPACE_RELATIVE
    ]:
        fail("desktop workspace members changed")
    if VENDOR_WORKSPACE_RELATIVE in workspace.get("exclude", []):
        fail("vendored glib native tests require workspace membership")
    if workspace.get("default-members") != ["mirror-core"]:
        fail("desktop default members must retain product-only scope")
    if desktop.get("patch", {}).get("crates-io", {}).get("glib") != {
        "path": "vendor/glib-0.18.5-rustsec-2024-0429"
    }:
        fail("desktop Cargo patch does not resolve the reviewed glib vendor path")

    package = load_toml(vendor / "Cargo.toml").get("package", {})
    if (package.get("name"), package.get("version"), package.get("license")) != (
        "glib",
        "0.18.5",
        "MIT",
    ):
        fail("vendored glib package identity changed")

    lock = load_toml(root / "desktop/Cargo.lock")
    matches = [item for item in lock.get("package", []) if item.get("name") == "glib"]
    if len(matches) != 1 or matches[0].get("version") != "0.18.5":
        fail("desktop lock must contain exactly glib 0.18.5")
    if "source" in matches[0] or "checksum" in matches[0]:
        fail("desktop lock restored glib to a registry source")


def verify_provenance(vendor):
    document = (vendor / "BACKPORT.md").read_text(encoding="utf-8")
    for value in (BASE_ARCHIVE_SHA256, UPSTREAM_URL, UPSTREAM_COMMIT, "&mut p", "MIT"):
        if value not in document:
            fail(f"BACKPORT.md is missing reviewed provenance: {value}")


def verify(root):
    vendor = root / VENDOR_RELATIVE
    files = vendor_files(vendor)
    records = inventory(vendor)
    if INVENTORY_NAME not in files:
        fail("vendor inventory is absent")
    files.pop(INVENTORY_NAME)
    verify_file_set(records, files)
    verify_digests(files, records)
    verify_pointer((vendor / "src/variant_iter.rs").read_text(encoding="utf-8"))
    verify_safe_apis(vendor)
    verify_provenance(vendor)
    verify_resolution(root, vendor)
    return {
        "schema": "shellx-drive.glib-backport-verification/v1",
        "status": "backport_verified",
        "safe_api_corrections": {
            "files": sorted(SAFE_API_CORRECTIONS),
            "verification": "source_and_inventory_only_native_tests_separate",
        },
        "known_advisory": {
            "id": "RUSTSEC-2024-0429",
            "status": "source_backport_verified_not_audit_waiver",
            "cargo_audit_0_22_2": {
                "path_patched_package": "omitted",
                "registry_reconstruction": "warnings.unsound",
                "verifier": "does_not_run_cargo_audit",
            },
            "upstream": UPSTREAM_URL,
        },
        "vendor": {
            "base_archive_sha256": BASE_ARCHIVE_SHA256,
            "files": EXPECTED_VENDOR_FILES,
            "inventory_sha256": sha256(vendor / INVENTORY_NAME),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    try:
        print(json.dumps(verify(arguments.root.resolve()), sort_keys=True))
    except VerificationError as error:
        print(f"verify_glib_backport: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
