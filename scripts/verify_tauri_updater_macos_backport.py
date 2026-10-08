#!/usr/bin/env python3
"""Verify the retained macOS updater replacement backport source."""

import argparse
import hashlib
import json
import os
import re
import sys
import tomllib
from pathlib import Path


VENDOR_RELATIVE = Path("desktop/vendor/tauri-plugin-updater-2.10.1-macos-backport")
VENDOR_WORKSPACE_RELATIVE = VENDOR_RELATIVE.relative_to("desktop").as_posix()
INVENTORY_NAME = "SHA256SUMS"
EXPECTED_VENDOR_FILES = 51
BASE_ARCHIVE_SHA256 = "806d9dac662c2e4594ff03c647a552f2c9bd544e7d0f683ec58f872f952ce4af"
BASE_REVISION = "d6a3898001a4bcc659e045f9501498751b77dbe6"
UPSTREAM_URL = "https://github.com/tauri-apps/plugins-workspace/blob/v2/plugins/updater/src/updater.rs"


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
        if relative == INVENTORY_NAME or any(part in {"", ".", ".."} for part in relative.split("/")):
            fail(f"unsafe inventory path at line {number}")
        if relative <= previous or relative in records:
            fail("inventory paths must be unique and sorted")
        previous = relative
        records[relative] = digest
    if len(records) != EXPECTED_VENDOR_FILES:
        fail(f"inventory must contain {EXPECTED_VENDOR_FILES} retained files")
    return records


def load_toml(path):
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read TOML {path}: {error}")


def require_values(source, values, description):
    missing = next((value for value in values if value not in source), None)
    if missing:
        fail(f"{description}: {missing}")


def verify_files(vendor):
    files = vendor_files(vendor)
    records = inventory(vendor)
    if INVENTORY_NAME not in files:
        fail("vendor inventory is absent")
    files.pop(INVENTORY_NAME)
    missing = sorted(set(records) - set(files))
    extra = sorted(set(files) - set(records))
    if missing or extra:
        fail(f"vendor file set changed; missing={missing}, extra={extra}")
    for relative, expected in records.items():
        if sha256(files[relative]) != expected:
            fail(f"vendor digest mismatch: {relative}")
    return records


def verify_resolution(root, vendor):
    desktop = load_toml(root / "desktop/Cargo.toml")
    workspace = desktop.get("workspace", {})
    if workspace.get("members") != ["mirror-core", "src-tauri", "updater-verifier", "vendor/glib-0.18.5-rustsec-2024-0429"]:
        fail("desktop workspace members changed")
    if VENDOR_WORKSPACE_RELATIVE not in workspace.get("exclude", []):
        fail("vendored updater must be excluded from workspace membership")
    if desktop.get("patch", {}).get("crates-io", {}).get("tauri-plugin-updater") != {
        "path": "vendor/tauri-plugin-updater-2.10.1-macos-backport"
    }:
        fail("desktop Cargo patch does not resolve the reviewed updater vendor path")

    package = load_toml(vendor / "Cargo.toml").get("package", {})
    if (package.get("name"), package.get("version"), package.get("license")) != (
        "tauri-plugin-updater", "2.10.1", "Apache-2.0 OR MIT"
    ):
        fail("vendored updater package identity changed")
    target = load_toml(vendor / "Cargo.toml").get("target", {})
    macos = target.get('cfg(target_os = "macos")', {}).get("dependencies", {})
    if macos.get("libc", {}).get("version") != "0.2":
        fail("vendored updater must retain its macOS-only libc dependency")

    lock = load_toml(root / "desktop/Cargo.lock")
    matches = [item for item in lock.get("package", []) if item.get("name") == "tauri-plugin-updater"]
    if len(matches) != 1 or matches[0].get("version") != "2.10.1":
        fail("desktop lock must contain exactly tauri-plugin-updater 2.10.1")
    if "source" in matches[0] or "checksum" in matches[0]:
        fail("desktop lock restored tauri-plugin-updater to a registry source")
def verify_backport(vendor):
    document = (vendor / "BACKPORT.md").read_text(encoding="utf-8")
    for value in (BASE_ARCHIVE_SHA256, BASE_REVISION, UPSTREAM_URL, "RENAME_EXCL", "quoted form of", "Linux AppImage"):
        if value not in document:
            fail(f"BACKPORT.md is missing reviewed provenance: {value}")
    updater = (vendor / "src/updater.rs").read_text(encoding="utf-8")
    signed_release = (vendor / "src/updater/signed_release.rs").read_text(encoding="utf-8")
    if updater.count("installed_package::current(&self.extract_path)") != 5:
        fail("updater package selection must agree across check, verification and installation")
    require_values((vendor / "src/updater/release_url_policy.rs").read_text(encoding="utf-8"), ('const GITHUB_HOST: &str = "github.com";', 'const REPOSITORY: &str = "martinsbrezauckis/shellx-drive";', "const MAX_REDIRECTS: usize = 3;", "pub(super) fn validate_feed_endpoint", "pub(super) fn validate_artifact_url", "pub(super) fn feed_redirect_policy", "pub(super) fn artifact_redirect_policy", "is_secure_public_url"), "fixed updater release transport policy")
    for value in ("mod signed_release;", "self.verify_signed_release(buffer.as_bytes())?;", "self.verify_signed_release(bytes.as_ref())?;", "signed_release::verify(", "mod release_url_policy;", "release_url_policy::validate_feed_endpoint(&url)", ".redirect(release_url_policy::feed_redirect_policy())", "release_url_policy::validate_artifact_url(download_url, &release.version, &platform)", "release_url_policy::validate_artifact_url(&self.download_url, &version, &platform)", "release_url_policy::artifact_redirect_policy(&version, &platform)", "request = request.redirect(redirect).referer(false);"):
        if value not in updater:
            fail(f"signed updater version binding is missing: {value}")
    bounds = (vendor / "src/updater/download_bounds.rs").read_text(encoding="utf-8")
    for value in (
        "MAX_UPDATE_FEED_BYTES: usize = 1024 * 1024",
        "MAX_COMPRESSED_INSTALLER_BYTES: usize = 512 * 1024 * 1024",
        ".checked_add(chunk)",
        "self.bytes.extend_from_slice(chunk)",
        '#[path = "download_bounds_tests.rs"]',
    ):
        if value not in bounds:
            fail(f"updater response bounds omit reviewed behavior: {value}")
    for value in (
        "mod download_bounds;",
        "download_bounds::MAX_UPDATE_FEED_BYTES",
        "download_bounds::MAX_COMPRESSED_INSTALLER_BYTES",
        "update_body.push(&chunk?)?;",
        "buffer.push_and_then(&chunk, || on_chunk(chunk.len(), content_length))?;",
    ):
        if value not in updater:
            fail(f"updater response bounds are not enforced: {value}")
    if "ResponseTooLarge {" not in (vendor / "src/error.rs").read_text(encoding="utf-8"):
        fail("updater response bounds lack a dedicated error")
    for value in ("key.verify(bytes, &signature, true)", "signature.trusted_comment()", "version.cmp_precedence(&current).is_gt()", "leaf != expected", "super::release_url_policy::validate_artifact_url(download_url, &version, platform)"):
        if value not in signed_release:
            fail(f"signed updater version binding is missing: {value}")
    if '#[cfg(target_os = "macos")]\nmod macos_replacement;' not in updater:
        fail("updater does not bind the macOS replacement helper")
    for value in (
        "macos_replace_with_authorization(",
        "macos_replace_staged_with_rollback(",
        "macos_rename_without_replacing(",
    ):
        if value not in updater:
            fail(f"updater omits reviewed macOS replacement behavior: {value}")
    for value in (
        "mod linux_replacement;",
        "linux_replacement::install_appimage(&self.extract_path, bytes)",
        "mod linux_privileges;",
    ):
        if value not in updater:
            fail(f"updater omits reviewed Linux replacement delegation: {value}")
    if any(value not in updater for value in (
        'linux_privileges::install_package(bytes, "/usr/bin/dpkg", "-i")',
        'linux_privileges::install_package(bytes, "/usr/bin/rpm", "-U")',
    )) or "fn try_tmp_locations(" in updater:
        fail("updater omits reviewed Linux package privilege delegation")
    helper = (vendor / "src/updater/macos_replacement.rs").read_text(encoding="utf-8")
    for value in (
        "libc::renameatx_np(",
        "libc::RENAME_EXCL,",
        "pub(super) fn macos_replace_with_authorization(",
        '#[path = "macos_replacement_tests.rs"]',
    ):
        if value not in helper:
            fail(f"macOS replacement helper omits reviewed safeguard: {value}")
    script = (vendor / "src/updater/macos_replacement.applescript").read_text(encoding="utf-8")
    for value in (
        "on replacement_command(",
        "quoted form of replacementScript",
        "do shell script command with administrator privileges",
    ):
        if value not in script:
            fail(f"macOS replacement AppleScript omits reviewed safeguard: {value}")
    probe = (vendor / "tests/macos_replacement_osakit.rs").read_text(encoding="utf-8")
    for value in (
        'include_str!("../src/updater/macos_replacement.applescript")',
        "osakit::Script::new_from_source",
        'execute_function("replacement_command", arguments)',
    ):
        if value not in probe:
            fail(f"macOS replacement OSAKit probe omits reviewed execution binding: {value}")
    linux = (vendor / "src/updater/linux_replacement.rs").read_text(encoding="utf-8")
    for value in (
        "tempfile_in(parent)",
        "validate_appimage(staged.as_file_mut())?",
        "staged.as_file().sync_all()?",
        "staged.persist(destination)",
        "archive.into_inner(), &mut std::io::sink()",
        '#[path = "linux_replacement_tests.rs"]',
    ):
        if value not in linux:
            fail(f"Linux AppImage replacement omits reviewed staging safeguard: {value}")
    privileges = (vendor / "src/updater/linux_privileges.rs").read_text(encoding="utf-8")
    for value in (
        "Ok(Some(status)) => return Err(pkexec_error(status))",
        "error.kind() == io::ErrorKind::NotFound",
        "std::str::from_utf8(&output).is_err()",
        ".stdout(Stdio::null())",
        ".stderr(Stdio::null())",
        "let _ = child.kill()",
        "let _ = child.wait()",
        'command.arg("-n")',
        '#[path = "linux_privileges_tests.rs"]',
    ):
        if value not in privileges:
            fail(f"Linux package privilege handling omits reviewed safeguard: {value}")
    if ".trim()" in privileges or "from_utf8_lossy" in privileges:
        fail("Linux package privilege handling must preserve password bytes")
    require_values(privileges, (
        "mod command_environment;",
        "use command_environment::privileged_command;",
        "mod sealed_package;",
        "let package = sealed_package::SealedPackage::new(bytes)?;",
        'PathBuf::from("/usr/bin/pkexec")',
        'PathBuf::from("/usr/bin/zenity")',
        'PathBuf::from("/usr/bin/kdialog")',
        'PathBuf::from("/usr/bin/sudo")',
    ), "Linux sealed package admission is incomplete")
    if privileges.count("privileged_command(program)") != 2 or privileges.count("privileged_command(&programs.sudo)") != 2:
        fail("Linux privilege command environment is not used by every helper")
    sealed_package = (vendor / "src/updater/linux_privileges/sealed_package.rs").read_text(encoding="utf-8")
    require_values(sealed_package, (
        "libc::memfd_create(",
        "libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING",
        "let mut file = unsafe { File::from_raw_fd(fd) };",
        "file.write_all(bytes)?;",
        "libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL",
        "libc::F_ADD_SEALS",
        "libc::F_GET_SEALS",
        "if observed & seals != seals",
        "verify_sealed_bytes(&mut file, bytes)?;",
        "file.metadata()?.len() != expected_len", "file.seek(SeekFrom::Start(0))?;",
        "for expected_chunk in expected.chunks(observed.len()) {", "file.read_exact(observed_chunk)?;",
        "if observed_chunk != expected_chunk",
        '#[path = "sealed_package_tests.rs"]',
    ), "Linux sealed package omits reviewed safeguard")
    if not re.search(
        r"file\.write_all\(bytes\)\?;.*F_ADD_SEALS.*F_GET_SEALS.*verify_sealed_bytes\(&mut file, bytes\)\?;.*Ok\(Self \{ _file: file, path \}\)",
        sealed_package,
        re.DOTALL,
    ):
        fail("Linux sealed package does not recheck signed bytes before exposure")
    command_environment = (vendor / "src/updater/linux_privileges/command_environment.rs").read_text(encoding="utf-8")
    require_values(command_environment, (
        'const PRIVILEGED_COMMAND_PATH: &str = "/usr/bin:/bin";',
        "INTERACTIVE_ENVIRONMENT",
        "privileged_command_with_environment(program, std::env::vars_os())",
        'command.env_clear().env("PATH", PRIVILEGED_COMMAND_PATH);',
        '#[path = "command_environment_tests.rs"]',
    ), "Linux privilege command environment omits reviewed safeguard")
    if re.search(r'"(?:LD_PRELOAD|LD_LIBRARY_PATH|BASH_ENV|HOME)"', command_environment):
        fail("Linux privilege command environment admits a hostile inherited variable")


def verify(root):
    vendor = root / VENDOR_RELATIVE
    verify_files(vendor)
    verify_resolution(root, vendor)
    verify_backport(vendor)
    return {
        "schema": "shellx-drive.tauri-updater-macos-backport-verification/v1",
        "status": "backport_verified",
        "vendor": {
            "base_archive_sha256": BASE_ARCHIVE_SHA256,
            "base_revision": BASE_REVISION,
            "files": EXPECTED_VENDOR_FILES,
            "inventory_sha256": sha256(vendor / INVENTORY_NAME),
        },
        "scope": "source integrity only; native or installed updater execution is not claimed",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    try:
        print(json.dumps(verify(arguments.root.resolve()), sort_keys=True))
    except VerificationError as error:
        print(f"verify_tauri_updater_macos_backport: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
