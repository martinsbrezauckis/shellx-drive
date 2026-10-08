use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    path::Path,
};

use super::{has_appimage_mount, mount_path, mounted_appimage};

fn image() -> (tempfile::TempDir, std::path::PathBuf, u32) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("Drive.AppImage");
    fs::write(&path, b"\x7fELF\x02\x01\x01\x00AI\x02test").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let uid = fs::metadata(&path).unwrap().uid();
    (directory, path, uid)
}

const EXECUTABLE: &str = "/tmp/.mount_Drive123/usr/bin/shellx-drive-desktop";
const MOUNTS: &str = "91 35 0:66 / /tmp/.mount_Drive123 ro,nosuid,nodev - fuse.Drive.AppImage Drive.AppImage ro,user_id=1000";

#[test]
fn installed_debian_uses_debian_and_refuses_an_inherited_appimage_target() {
    let installed = Path::new("/usr/bin/shellx-drive-desktop");
    assert!(matches!(
        super::package_for_paths(installed, installed),
        Some(super::Installer::Deb)
    ));
    let (_directory, image, _uid) = image();
    assert!(super::package_for_paths(&image, installed).is_none());
}

#[test]
fn raw_appimage_package_is_selected_from_live_mount_and_outer_image() {
    let (_directory, path, uid) = image();
    assert!(mounted_appimage(&path, Path::new(EXECUTABLE), MOUNTS, uid));
    assert!(!mounted_appimage(&path, Path::new(EXECUTABLE), "", uid));
    assert!(!mounted_appimage(
        &path,
        Path::new(EXECUTABLE),
        &MOUNTS.replace("fuse.Drive.AppImage", "ext4"),
        uid
    ));
    assert!(!mounted_appimage(
        &path,
        Path::new("/usr/bin/shellx-drive-desktop"),
        MOUNTS,
        uid
    ));
    assert!(!mounted_appimage(
        &path,
        Path::new("/tmp/.mount_Drive123-other/usr/bin/shellx-drive-desktop"),
        MOUNTS,
        uid
    ));
}

#[test]
fn inherited_appimage_cannot_turn_a_raw_development_binary_into_a_package() {
    let (_directory, path, uid) = image();
    assert!(!mounted_appimage(
        &path,
        Path::new("/tmp/target/debug/shellx-drive-desktop"),
        MOUNTS,
        uid
    ));
    let current = super::super::current_exe().unwrap();
    assert!(super::current(&current).is_none());
}

#[test]
fn outer_image_must_be_regular_executable_owner_safe_and_type_two() {
    let (_directory, path, uid) = image();
    let executable = Path::new(EXECUTABLE);
    let alias = path.with_extension("link");
    symlink(&path, &alias).unwrap();
    assert!(!mounted_appimage(&alias, executable, MOUNTS, uid));
    assert!(!mounted_appimage(
        Path::new("Drive.AppImage"),
        executable,
        MOUNTS,
        uid
    ));
    assert!(!mounted_appimage(
        &path,
        executable,
        MOUNTS,
        uid.wrapping_add(1)
    ));
    for mode in [0o600, 0o702, 0o720] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(!mounted_appimage(&path, executable, MOUNTS, uid));
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    for bytes in [
        b"not an AppImage".as_slice(),
        b"\x7fELF\x02\x01\x01\x00AI\x01test",
        b"\x7fELF",
    ] {
        fs::write(&path, bytes).unwrap();
        assert!(!mounted_appimage(&path, executable, MOUNTS, uid));
    }
}

#[test]
fn mount_paths_decode_kernel_escapes_and_require_exact_packaged_binary() {
    let mounts = MOUNTS.replace(".mount_Drive123", ".mount_Drive\\040123");
    assert!(has_appimage_mount(
        Path::new("/tmp/.mount_Drive 123/usr/bin/shellx-drive-desktop"),
        &mounts
    ));
    assert!(!has_appimage_mount(
        Path::new("/tmp/.mount_Drive 123/usr/bin/other"),
        &mounts
    ));
    assert_eq!(
        mount_path("/tmp/Drive\\040name"),
        Some("/tmp/Drive name".into())
    );
    for path in ["/tmp/Drive\\", "/tmp/Drive\\08x", "/tmp/Drive\\777"] {
        assert!(mount_path(path).is_none());
    }
}
