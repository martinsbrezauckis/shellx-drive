// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use super::*;
use std::os::unix::fs::PermissionsExt;

fn image(marker: &[u8]) -> Vec<u8> {
    let mut bytes = b"\x7fELF\x02\x01\x01\x00AI\x02".to_vec();
    bytes.extend_from_slice(marker);
    bytes
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, Vec<u8>) {
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("Drive's 雪.AppImage");
    let original = image(b"original installed app");
    fs::write(&destination, &original).unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o751)).unwrap();
    (root, destination, original)
}

fn assert_preserved(root: &Path, destination: &Path, original: &[u8]) {
    assert_eq!(fs::read(destination).unwrap(), original);
    assert_eq!(
        fs::metadata(destination).unwrap().permissions().mode() & 0o777,
        0o751
    );
    assert_eq!(
        fs::read_dir(root).unwrap().count(),
        1,
        "failed staging is cleaned up"
    );
}

#[test]
fn raw_appimage_replacement_preserves_mode_and_cleans_staging() {
    let (root, destination, _) = fixture();
    let replacement = image(b"new verified app");
    install_appimage(&destination, &replacement).unwrap();
    assert_preserved(root.path(), &destination, &replacement);
}

#[test]
fn invalid_raw_appimage_preserves_installed_file() {
    let (root, destination, original) = fixture();
    assert!(install_appimage(&destination, b"not an AppImage").is_err());
    assert_preserved(root.path(), &destination, &original);
}

#[test]
fn symlink_destination_is_not_replaced() {
    let (root, destination, original) = fixture();
    let link = root.path().join("alias.AppImage");
    std::os::unix::fs::symlink(&destination, &link).unwrap();
    assert!(install_appimage(&link, &image(b"new app")).is_err());
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(destination).unwrap(), original);
}

#[cfg(feature = "zip")]
fn archive(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (name, contents) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        archive
            .append_data(&mut header, name, contents.as_slice())
            .unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap()
}

#[cfg(feature = "zip")]
#[test]
fn archive_replacement_preserves_installed_executable_mode() {
    let (root, destination, _) = fixture();
    let replacement = image(b"new compressed app");
    let bytes = archive(&[("Drive.AppImage", replacement.clone())]);
    install_appimage(&destination, &bytes).unwrap();
    assert_preserved(root.path(), &destination, &replacement);
}

#[cfg(feature = "zip")]
#[test]
fn truncated_gzip_preserves_installed_file() {
    let (root, destination, original) = fixture();
    let mut bytes = archive(&[("Drive.AppImage", image(b"new app"))]);
    bytes.truncate(bytes.len() - 5);
    assert!(install_appimage(&destination, &bytes).is_err());
    assert_preserved(root.path(), &destination, &original);
}

#[cfg(feature = "zip")]
#[test]
fn gzip_checksum_failure_preserves_installed_file() {
    let (root, destination, original) = fixture();
    let mut bytes = archive(&[("Drive.AppImage", image(b"new app"))]);
    let checksum = bytes.len() - 8;
    bytes[checksum] ^= 1;
    assert!(install_appimage(&destination, &bytes).is_err());
    assert_preserved(root.path(), &destination, &original);
}

#[cfg(feature = "zip")]
#[test]
fn archive_link_is_not_an_executable_replacement() {
    let (root, destination, original) = fixture();
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    header.set_cksum();
    archive
        .append_link(&mut header, "Drive.AppImage", "/outside")
        .unwrap();
    let bytes = archive.into_inner().unwrap().finish().unwrap();
    assert!(install_appimage(&destination, &bytes).is_err());
    assert_preserved(root.path(), &destination, &original);
}

#[cfg(feature = "zip")]
#[test]
fn missing_or_duplicate_archive_appimages_preserve_installed_file() {
    for entries in [
        vec![("readme.txt", b"no app".to_vec())],
        vec![
            ("one.AppImage", image(b"one")),
            ("two.AppImage", image(b"two")),
        ],
    ] {
        let (root, destination, original) = fixture();
        assert!(install_appimage(&destination, &archive(&entries)).is_err());
        assert_preserved(root.path(), &destination, &original);
    }
}
