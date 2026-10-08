use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use super::*;

#[test]
fn xdg_autostart_migration_removes_only_the_known_owned_legacy_entry() {
    let directory = tempfile::tempdir().unwrap();
    let current = directory.path().join("xdg").join(AUTOSTART_FILE);
    let legacy = directory
        .path()
        .join(".config")
        .join("autostart")
        .join(AUTOSTART_FILE);
    fs::create_dir_all(current.parent().unwrap()).unwrap();
    fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    fs::write(&current, format!("{AUTOSTART_OWNERSHIP_MARKER}\n")).unwrap();
    fs::write(&legacy, format!("{AUTOSTART_OWNERSHIP_MARKER}\n")).unwrap();
    fs::set_permissions(&current, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o600)).unwrap();

    remove_owned_autostart_entries(&current, Some(legacy.clone())).unwrap();
    assert!(!current.exists());
    assert!(!legacy.exists());

    fs::write(&current, "[Desktop Entry]\nType=Application\n").unwrap();
    fs::write(&legacy, format!("{AUTOSTART_OWNERSHIP_MARKER}\n")).unwrap();
    fs::set_permissions(&current, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(remove_owned_autostart_entries(&current, Some(legacy.clone())).is_err());
    assert!(current.exists());
    assert!(!legacy.exists());

    fs::write(&legacy, "[Desktop Entry]\nType=Application\n").unwrap();
    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o600)).unwrap();
    cleanup_known_legacy_after_enable(&current, Some(legacy.clone()));
    assert!(legacy.exists());
}

#[test]
fn xdg_autostart_migration_uses_current_config_and_dedupes_default() {
    let home = Path::new("/home/drive");
    let custom = Path::new("/run/user/1000/drive-config");
    let (current, legacy) = linux_autostart_paths(home, custom);
    assert_eq!(current, custom.join("autostart").join(AUTOSTART_FILE));
    assert_eq!(
        legacy,
        Some(home.join(".config").join("autostart").join(AUTOSTART_FILE))
    );

    let default = home.join(".config");
    assert_eq!(linux_autostart_paths(home, &default).1, None);
}

#[test]
fn xdg_autostart_alias_does_not_remove_the_current_registration() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path();
    let config = home.join(".config").join("..").join(".config");
    let (current, legacy) = linux_autostart_paths(home, &config);
    let legacy = legacy.expect("the textual alias is retained for later identity checking");
    fs::create_dir_all(current.parent().unwrap()).unwrap();
    fs::write(&current, format!("{AUTOSTART_OWNERSHIP_MARKER}\n")).unwrap();
    fs::set_permissions(&current, fs::Permissions::from_mode(0o600)).unwrap();

    cleanup_known_legacy_after_enable(&current, Some(legacy));
    assert!(current.exists());
}
