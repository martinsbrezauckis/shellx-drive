use std::{ffi::OsStr, os::unix::fs::PermissionsExt};

use super::*;

#[test]
fn autostart_representation_is_platform_specific() {
    let path = autostart_path().unwrap();
    assert_eq!(path.file_name(), Some(OsStr::new(AUTOSTART_FILE)));
    let base = BaseDirs::new().unwrap();
    #[cfg(target_os = "linux")]
    assert_eq!(path.parent().unwrap(), base.config_dir().join("autostart"));
    #[cfg(target_os = "macos")]
    assert_eq!(
        path.parent().unwrap(),
        base.home_dir().join("Library/LaunchAgents")
    );
}

#[test]
fn autostart_cleanup_removes_only_a_private_marked_entry() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(AUTOSTART_FILE);
    fs::write(&path, "[Desktop Entry]\nType=Application\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(remove_owned_autostart(&path).is_err());
    assert!(path.exists());

    fs::write(&path, format!("{AUTOSTART_OWNERSHIP_MARKER}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    remove_owned_autostart(&path).unwrap();
    assert!(!path.exists());
}

#[test]
fn stable_executable_rejects_relative_symlink_and_writable_paths() {
    let directory = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(std::env::var_os("HOME").unwrap())
        .unwrap();
    let executable = directory.path().join("shellx-drive-desktop");
    fs::write(&executable, b"binary").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(executable::validate_stable_executable(&executable, false).is_ok());
    assert!(executable::validate_stable_executable(Path::new("relative"), false).is_err());

    let linked = directory.path().join("linked");
    std::os::unix::fs::symlink(&executable, &linked).unwrap();
    assert!(executable::validate_stable_executable(&linked, false).is_err());

    fs::set_permissions(&executable, fs::Permissions::from_mode(0o707)).unwrap();
    assert!(executable::validate_stable_executable(&executable, false).is_err());

    fs::set_permissions(&executable, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(executable::validate_stable_executable(&executable, false).is_err());
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o770)).unwrap();
    assert!(executable::validate_stable_executable(&executable, false).is_err());

    let untrusted_ancestor = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    let staged = untrusted_ancestor.path().join("shellx-drive-desktop");
    fs::write(&staged, b"binary").unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(executable::validate_stable_executable(&staged, false).is_err());
}

#[test]
fn macos_applications_exception_requires_the_system_admin_boundary() {
    // The observed group number is deliberately not the usual macOS gid:
    // admission must use the resolved system group, not a numeric pin.
    let admin = 731;
    assert!(executable::macos_system_applications_is_trusted(
        Path::new("/Applications"),
        0,
        admin,
        0o775,
        Some(admin)
    ));
    for (path, owner, group, mode, resolved) in [
        ("/Applications", 0, admin, 0o777, Some(admin)),
        ("/Applications", 501, admin, 0o775, Some(admin)),
        ("/Applications", 0, 80, 0o775, Some(admin)),
        ("/Applications", 0, admin, 0o775, None),
        ("/Applications/Drive.app", 0, admin, 0o775, Some(admin)),
        (
            "/Applications/Drive.app/Contents",
            0,
            admin,
            0o775,
            Some(admin),
        ),
        ("/Other/Applications", 0, admin, 0o775, Some(admin)),
        ("/Other", 0, admin, 0o775, Some(admin)),
    ] {
        assert!(
            !executable::macos_system_applications_is_trusted(
                Path::new(path),
                owner,
                group,
                mode,
                resolved
            ),
            "unexpected Applications exception for {path}"
        );
    }
}

#[test]
fn executable_admission_guidance_names_the_native_installation() {
    let error = executable::validate_stable_executable(Path::new("relative"), false)
        .unwrap_err()
        .to_string();
    #[cfg(target_os = "macos")]
    {
        assert!(error.contains("/Applications"));
        assert!(!error.contains("AppImage"));
    }
    #[cfg(target_os = "linux")]
    assert!(error.contains("AppImage"));
}

#[cfg(target_os = "linux")]
#[test]
fn appimage_mount_paths_are_never_selected_without_the_original_appimage() {
    assert!(executable::path_is_transient_appimage_location(Path::new(
        "/tmp/.mount_shellx-drive/shellx-drive-desktop"
    ))
    .unwrap());
    assert!(executable::path_is_transient_appimage_location(Path::new(
        "/var/tmp/shellx-drive.AppImage"
    ))
    .unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn appimage_launch_at_login_uses_only_the_validated_original_file() {
    let home = std::env::var_os("HOME").expect("ordinary user has HOME");
    let directory = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .prefix("shellx-drive-appimage-test-")
        .tempdir_in(home)
        .unwrap();
    let original = directory.path().join("ShellX-Drive.AppImage");
    fs::write(&original, b"appimage").unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();

    let selected = executable::select_stable_executable(
        Path::new("/tmp/.mount_shellx-drive/shellx-drive-desktop"),
        Some(original.as_os_str()),
    )
    .unwrap();

    assert_eq!(selected, fs::canonicalize(&original).unwrap());
    assert!(executable::select_stable_executable(
        Path::new("/usr/bin/false"),
        Some(OsStr::new("/tmp/Drive.AppImage")),
    )
    .is_err());
}

#[test]
fn generated_entry_carries_exact_ownership_marker() {
    let directory = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(std::env::var_os("HOME").unwrap())
        .unwrap();
    let executable = directory.path().join("shellx-drive-desktop");
    fs::write(&executable, b"binary").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(autostart_contents_are_owned(
        &autostart_contents_for(
            &executable::validate_stable_executable(&executable, false).unwrap(),
        )
        .unwrap()
    ));
}
