use super::*;

#[test]
fn autostart_representation_is_platform_specific() {
    let path = autostart_path().unwrap();
    assert_eq!(path.file_name(), Some(OsStr::new(AUTOSTART_FILE)));
    let parent = path.parent().unwrap();
    assert_eq!(parent.file_name(), Some(OsStr::new(AUTOSTART_DIRECTORY[1])));
    assert_eq!(
        parent.parent().unwrap().file_name(),
        Some(OsStr::new(AUTOSTART_DIRECTORY[0]))
    );
}

#[test]
fn generated_autostart_entry_carries_an_exact_ownership_marker() {
    assert!(autostart_contents_are_owned(&autostart_contents().unwrap()));
    assert!(!autostart_contents_are_owned(
        "[Desktop Entry]\nType=Application\nExec=/someone-else\n"
    ));
}

#[test]
fn autostart_cleanup_removes_only_the_marked_entry() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(AUTOSTART_FILE);
    fs::write(&path, "[Desktop Entry]\nType=Application\n").unwrap();
    assert!(remove_owned_autostart(&path).is_err());
    assert!(path.exists());

    fs::write(&path, autostart_contents().unwrap()).unwrap();
    remove_owned_autostart(&path).unwrap();
    assert!(!path.exists());
}
