#!/usr/bin/env python3
"""Authenticate a Linux candidate before install and its closure after install."""
import argparse
import hashlib
import os
import pathlib
import stat
import sys
import types

ATTESTATION = "linux-verifier-attestation.v1.json"
RECEIPT_SCHEMA = "shellx-drive.linux-trusted-release-verification/v1"
MODULES = ("verify-linux-trusted-common.py", "verify-linux-trusted-candidate.py")
KEYRING_NAME = "shellx-drive-linux-release-keyring.gpg"


def load_trusted_module(bundle, leaf, module_name):
    path = bundle / leaf
    try:
        observed = os.lstat(path)
        if not stat.S_ISREG(observed.st_mode) or stat.S_ISLNK(observed.st_mode) or observed.st_nlink != 1 or observed.st_mode & 0o022 or observed.st_size > 256 * 1024:
            raise RuntimeError("unsafe file identity")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(fd)
            chunks = []
            while chunk := os.read(fd, 64 * 1024):
                chunks.append(chunk)
            after = os.fstat(fd)
            current = os.lstat(path)
        finally:
            os.close(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if tuple(getattr(before, key) for key in fields) != tuple(getattr(after, key) for key in fields) or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino):
            raise RuntimeError("file changed while read")
        source = b"".join(chunks).decode("utf-8", "strict")
        module = types.ModuleType(module_name)
        module.__file__ = str(path)
        module.__trusted_identity__ = {"sha256": hashlib.sha256(b"".join(chunks)).hexdigest(), "size": after.st_size, "mode": f"{stat.S_IMODE(after.st_mode):04o}"}
        exec(compile(source, str(path), "exec"), module.__dict__)
        return module
    except (OSError, RuntimeError, UnicodeDecodeError, SyntaxError) as error:
        raise SystemExit(f"FAIL: trusted verification bundle module {leaf} is invalid: {error}") from None


def trusted_bundle_modules():
    script = pathlib.Path(__file__)
    if not script.is_absolute() or script.is_symlink() or os.path.realpath(script) != str(script):
        raise SystemExit("FAIL: trusted verifier must be invoked by its normalized absolute non-symlink path")
    bundle = script.parent
    if os.path.realpath(bundle) != str(bundle):
        raise SystemExit("FAIL: trusted verifier bundle must not resolve through a symlink")
    sys.dont_write_bytecode = True
    trust = load_trusted_module(bundle, MODULES[0], "shellx_drive_linux_trusted_common")
    candidate = load_trusted_module(bundle, MODULES[1], "shellx_drive_linux_trusted_candidate")
    return bundle, trust, candidate


def parse_arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate-dir", "attestation", "attestation-signature", "keyring", "pinned-fingerprint", "output-receipt"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--installed-root")
    return parser.parse_args()


def main():
    bundle, trust, candidate = trusted_bundle_modules()
    args = parse_arguments()
    if not candidate.FINGERPRINT.fullmatch(args.pinned_fingerprint):
        trust.fail("pinned fingerprint must be full uppercase hexadecimal")
    root = trust.normalized(args.candidate_dir, "candidate directory", True)
    attestation_path = trust.normalized(args.attestation, "terminal attestation")
    signature_path = trust.normalized(args.attestation_signature, "terminal attestation signature")
    keyring_path = trust.normalized(args.keyring, "external release keyring")
    if attestation_path.parent != root or attestation_path.name != ATTESTATION or signature_path != pathlib.Path(f"{attestation_path}.asc"):
        trust.fail("attestation and signature must use fixed candidate-root names")
    if os.path.commonpath((str(root), str(keyring_path))) == str(root):
        trust.fail("release keyring must come from the external verification bundle")
    attestation = trust.stable_bytes(str(attestation_path), "terminal attestation", trust.MAX_DOCUMENT)
    signature = trust.stable_bytes(str(signature_path), "terminal attestation signature", trust.MAX_SIGNATURE)
    keyring = trust.stable_bytes(str(keyring_path), "external release keyring", trust.MAX_KEYRING)
    trust.verify_signature(attestation, signature, keyring, args.pinned_fingerprint, "terminal attestation")
    value = trust.parse_json(attestation, "terminal attestation", True)
    candidate.validate_attestation(value, args.pinned_fingerprint, trust)
    keyring_identity = trust.stable_hash(str(keyring_path), "external release keyring")
    bundle_identity = {
        pathlib.Path(__file__).name: trust.stable_hash(str(pathlib.Path(__file__)), "external verifier entrypoint"),
        MODULES[0]: trust.__trusted_identity__,
        MODULES[1]: candidate.__trusted_identity__,
        KEYRING_NAME: keyring_identity,
    }
    if bundle_identity != value["externalVerificationBundle"]:
        trust.fail("external verification bundle differs from signed terminal identity")
    expected_keyring = value["packageFiles"]["deb"][candidate.LAYOUT["releaseKeyringPath"]]
    if keyring_identity["sha256"] != expected_keyring["sha256"] or keyring_identity["size"] != expected_keyring["size"]:
        trust.fail("external release keyring differs from signed package keyring")
    candidate.verify_candidate(value, root, keyring, args.pinned_fingerprint, trust)
    phase = "post-install" if args.installed_root else "pre-install"
    if args.installed_root:
        candidate.verify_installed(value, args.installed_root, trust)
    installed_binary = value["packageFiles"]["deb"][candidate.LAYOUT["desktopBinaryPath"]]
    receipt = {"artifacts": value["artifacts"], "attestationSha256": hashlib.sha256(attestation).hexdigest(), "installedBinary": installed_binary, "keyringSha256": keyring_identity["sha256"], "phase": phase, "pinnedFingerprint": args.pinned_fingerprint, "schema": RECEIPT_SCHEMA, "source": value["source"], "status": "pass"}
    trust.receipt_output(args.output_receipt, receipt)
    print(f"LINUX_TRUSTED_RELEASE_OK phase={phase} receipt={args.output_receipt}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        if error.__class__.__name__ != "VerificationError":
            raise
        raise SystemExit(f"FAIL: {error}") from None
