use std::{fs, os::unix::fs::OpenOptionsExt, path::Path};

use super::super::super::{test_fixture_directory, ReplacingPublication, UnixRootGuard};

#[test]
fn late_local_edit_discards_batch_before_exchange() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).unwrap();
    let staging = shellx_drive_desktop_core::download_staging_root(&root).unwrap();
    let owned =
        shellx_drive_desktop_core::initialize_owned_staging_root(&root, &staging, "download")
            .unwrap();
    let batch = owned.create_batch(2).unwrap();
    fs::write(root.join("report.txt"), b"baseline").unwrap();
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
    let guard = UnixRootGuard::acquire(&root, None).unwrap();
    let expected = guard.local_regular_entry(Path::new("report.txt")).unwrap();
    let prepared = guard
        .prepare_staged_file_replacement(&staged, Path::new("report.txt"), &expected)
        .unwrap()
        .expect("baseline prepares replacement");

    fs::write(root.join("report.txt"), b"late-local-edit").unwrap();
    assert_eq!(
        prepared.publish(&guard, || Ok(())).unwrap(),
        ReplacingPublication::NeedsReview {
            recovery_leaf: None
        }
    );
    assert_eq!(
        fs::read(root.join("report.txt")).unwrap(),
        b"late-local-edit"
    );
    assert_eq!(fs::read(&staged).unwrap(), b"remote");
    assert_eq!(fs::read(batch.join("local-recovery")).unwrap(), b"baseline");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    crate::platform::unix::download_space::finish_failed_download(&owned, &batch, false).unwrap();
    assert!(!batch.exists());
}
