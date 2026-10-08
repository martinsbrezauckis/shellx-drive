#!/usr/bin/env python3
"""Verify a signed Linux candidate's non-secret identity and byte integrity."""
import argparse
import hashlib
import json
import re
import stat
from pathlib import Path

SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
FINGERPRINT = re.compile(r"^[A-F0-9]{40}$")


def fail(message):
    raise SystemExit(f"FAIL: {message}")


def regular(path, label):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is missing")
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
        fail(f"{label} must be a single-link regular file")


def child(root, name, label):
    if not isinstance(name, str) or name != Path(name).name or name in ("", ".", ".."):
        fail(f"{label} file name is unsafe")
    path = root / name
    if path.parent != root:
        fail(f"{label} escaped the candidate directory")
    regular(path, label)
    return path


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--candidate-dir", required=True)
parser.add_argument("--manifest", required=True)
parser.add_argument("--expected-fingerprint", required=True)
arguments = parser.parse_args()
candidate_input = Path(arguments.candidate_dir)
manifest_input = Path(arguments.manifest)
try:
    candidate_metadata = candidate_input.lstat()
    manifest_metadata = manifest_input.lstat()
except FileNotFoundError:
    fail("candidate directory or manifest is missing")
if not stat.S_ISDIR(candidate_metadata.st_mode) or stat.S_ISLNK(candidate_metadata.st_mode) or stat.S_ISLNK(manifest_metadata.st_mode):
    fail("candidate directory and manifest must not be symlinks")
root = candidate_input.resolve(strict=True)
manifest_path = manifest_input.resolve(strict=True)
if manifest_path.parent != root:
    fail("candidate directory and manifest must be the same non-symlinked directory")
regular(manifest_path, "candidate manifest")
if not FINGERPRINT.fullmatch(arguments.expected_fingerprint):
    fail("expected release key fingerprint must be full uppercase hexadecimal")
try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    fail(f"candidate manifest is invalid: {error}")
if not isinstance(manifest, dict) or manifest.get("schema") != "shellx-drive.linux-candidate/v1":
    fail("candidate manifest schema is not admitted")
source = manifest.get("source")
signer = manifest.get("signer")
artifacts = manifest.get("artifacts")
updaters = manifest.get("updaters")
if not isinstance(source, dict) or not COMMIT.fullmatch(source.get("commit", "")) or not COMMIT.fullmatch(source.get("tree", "")):
    fail("candidate source identity is malformed")
if not isinstance(signer, dict) or signer.get("release_key_fingerprint") != arguments.expected_fingerprint:
    fail("candidate signer identity does not match the expected release key")
if not isinstance(artifacts, dict) or not isinstance(updaters, dict) or set(updaters) != {"linux-x86_64", "linux-x86_64-deb"}:
    fail("candidate artifact or updater mapping is malformed")
for label in ("appimage", "deb"):
    item = artifacts.get(label)
    if not isinstance(item, dict) or not SHA256.fullmatch(item.get("sha256", "")):
        fail(f"{label} integrity metadata is malformed")
    path = child(root, item.get("file"), label)
    if sha256(path) != item["sha256"]:
        fail(f"{label} bytes do not match the authenticated manifest")
for platform, artifact in (("linux-x86_64", "appimage"), ("linux-x86_64-deb", "deb")):
    updater = updaters[platform]
    if not isinstance(updater, dict) or set(updater) != {"artifact", "signature", "artifact_sha256", "signature_sha256"}:
        fail(f"{platform} updater mapping is malformed")
    if updater.get("artifact") != artifacts[artifact]["file"] or updater.get("artifact_sha256") != artifacts[artifact]["sha256"]:
        fail(f"{platform} updater does not bind the authenticated {artifact}")
    if not SHA256.fullmatch(updater.get("signature_sha256", "")):
        fail(f"{platform} updater signature integrity metadata is malformed")
    signature = child(root, updater.get("signature"), f"{platform} updater signature")
    if sha256(signature) != updater["signature_sha256"]:
        fail(f"{platform} updater signature bytes do not match the authenticated manifest")
print(f"LINUX_CANDIDATE_MANIFEST_OK source_commit={source['commit']} source_tree={source['tree']}")
