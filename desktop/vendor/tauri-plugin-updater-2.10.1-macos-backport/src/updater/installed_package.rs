//! Package selection for Drive's separately built and signed raw executables.
//! These packagers preserve Tauri's unknown bundle marker. Selection must use
//! local installation facts, never the untrusted update manifest.

use std::path::Path;

use super::{bundle_type, installer_for_bundle_type, Installer};

pub(super) fn current(extract_path: &Path) -> Option<Installer> {
    installer_for_bundle_type(bundle_type()).or_else(|| raw_package(extract_path))
}

#[cfg(target_os = "windows")]
fn raw_package(_extract_path: &Path) -> Option<Installer> {
    // Drive ships only NSIS on Windows. The existing raw-PE signer preserves
    // executable content, and a raw build could already invoke signed NSIS.
    Some(Installer::Nsis)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn raw_package(_extract_path: &Path) -> Option<Installer> {
    None
}

#[cfg(target_os = "linux")]
fn raw_package(extract_path: &Path) -> Option<Installer> {
    package_for_paths(extract_path, &super::current_exe().ok()?)
}

#[cfg(target_os = "linux")]
fn package_for_paths(extract_path: &Path, executable: &Path) -> Option<Installer> {
    use std::os::unix::fs::MetadataExt;

    if executable == Path::new("/usr/bin/shellx-drive-desktop") {
        // An inherited APPIMAGE must not divert an installed Debian client.
        return (extract_path == executable).then_some(Installer::Deb);
    }
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let uid = std::fs::metadata("/proc/self").ok()?.uid();
    mounted_appimage(extract_path, executable, &mounts, uid).then_some(Installer::AppImage)
}

#[cfg(target_os = "linux")]
fn mounted_appimage(outer: &Path, executable: &Path, mounts: &str, uid: u32) -> bool {
    use std::{fs, io::Read, os::unix::fs::MetadataExt};

    if !outer.is_absolute() || outer == executable || !has_appimage_mount(executable, mounts) {
        return false;
    }
    let Ok(metadata) = fs::symlink_metadata(outer) else {
        return false;
    };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return false;
    }
    let Ok(mut file) = fs::File::open(outer) else {
        return false;
    };
    let Ok(opened) = file.metadata() else {
        return false;
    };
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return false;
    }
    let mut header = [0u8; 11];
    file.read_exact(&mut header).is_ok()
        && &header[..4] == b"\x7fELF"
        && &header[8..11] == b"AI\x02"
}

#[cfg(target_os = "linux")]
fn has_appimage_mount(executable: &Path, mounts: &str) -> bool {
    mounts.lines().any(|line| {
        let Some((left, right)) = line.split_once(" - ") else {
            return false;
        };
        if !right
            .split_whitespace()
            .next()
            .is_some_and(|fs| fs.starts_with("fuse"))
        {
            return false;
        }
        let Some(mountpoint) = left.split_whitespace().nth(4).and_then(mount_path) else {
            return false;
        };
        mountpoint.is_absolute() && mountpoint.join("usr/bin/shellx-drive-desktop") == executable
    })
}

#[cfg(target_os = "linux")]
fn mount_path(value: &str) -> Option<std::path::PathBuf> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let mut path = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'\\' {
            let encoded = [bytes.next()?, bytes.next()?, bytes.next()?];
            if !encoded.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
                return None;
            }
            let decoded = (encoded[0] - b'0') as u16 * 64
                + (encoded[1] - b'0') as u16 * 8
                + (encoded[2] - b'0') as u16;
            path.push(u8::try_from(decoded).ok()?);
        } else {
            path.push(byte);
        }
    }
    Some(OsString::from_vec(path).into())
}

#[cfg(all(test, target_os = "linux"))]
#[path = "installed_package_tests.rs"]
mod tests;
