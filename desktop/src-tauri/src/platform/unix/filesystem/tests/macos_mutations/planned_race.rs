use std::{fs, os::unix::fs::OpenOptionsExt, path::Path};

use super::super::super::{test_fixture_directory, UnixRootGuard};

#[test]
fn edit_after_planning_cannot_become_the_replacement_authority() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).unwrap();
    let staging = shellx_drive_desktop_core::download_staging_root(&root).unwrap();
    let owned =
        shellx_drive_desktop_core::initialize_owned_staging_root(&root, &staging, "download")
            .unwrap();
    let batch = owned.create_batch(3).unwrap();
    fs::write(root.join("report.txt"), b"planned-body").unwrap();
    let guard = UnixRootGuard::acquire(&root, None).unwrap();
    let planned = guard.local_regular_entry(Path::new("report.txt")).unwrap();
    fs::write(root.join("report.txt"), b"edit-after-plan").unwrap();
    let staged = batch.join("payload");
    let mut staged_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)
        .unwrap();
    use std::io::Write;
    staged_file.write_all(b"remote").unwrap();
    drop(staged_file);

    assert!(guard
        .prepare_staged_file_replacement(&staged, Path::new("report.txt"), &planned)
        .unwrap()
        .is_none());
    assert_eq!(
        fs::read(root.join("report.txt")).unwrap(),
        b"edit-after-plan"
    );
    assert_eq!(fs::read(&staged).unwrap(), b"remote");
    assert!(!batch.join("local-recovery").exists());
}
