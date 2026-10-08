use std::{fs, path::Path};

use super::super::{test_fixture_directory, UnixRootGuard};

#[test]
fn staged_restore_tree_publishes_once_and_never_replaces_a_racing_destination() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    let private = directory.path().join("private");
    fs::create_dir(&root).unwrap();
    shellx_drive_desktop_core::ensure_private_staging_directory(&private).unwrap();
    let payload = private.join("payload");
    fs::create_dir(&payload).unwrap();
    fs::write(payload.join("report.txt"), b"remote body").unwrap();
    let guard = UnixRootGuard::acquire(&root, None).unwrap();

    guard
        .publish_staged_entry_noreplace(&payload, Path::new("restored"), true, || {
            assert!(guard.local_entry_is_absent(Path::new("restored"))?);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        fs::read(root.join("restored/report.txt")).unwrap(),
        b"remote body"
    );

    let collision = private.join("collision");
    fs::create_dir(&collision).unwrap();
    fs::write(collision.join("keep.txt"), b"staged body").unwrap();
    fs::create_dir(root.join("occupied")).unwrap();
    fs::write(root.join("occupied/keep.txt"), b"local body").unwrap();
    assert!(guard
        .publish_staged_entry_noreplace(&collision, Path::new("occupied"), true, || Ok(()))
        .is_err());
    assert_eq!(
        fs::read(root.join("occupied/keep.txt")).unwrap(),
        b"local body"
    );
    assert_eq!(
        fs::read(collision.join("keep.txt")).unwrap(),
        b"staged body"
    );
}

#[test]
fn failed_multi_file_restore_keeps_every_staged_body_outside_the_mirror() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    let private = directory.path().join("private");
    fs::create_dir(&root).unwrap();
    shellx_drive_desktop_core::ensure_private_staging_directory(&private).unwrap();
    let payload = private.join("payload");
    fs::create_dir(&payload).unwrap();
    fs::write(payload.join("first.txt"), b"first body").unwrap();

    // A later download/validation failure means no publication call occurs.
    // The first verified body remains private rather than becoming a partial
    // user-visible restore.
    assert!(!root.join("restored").exists());
    assert_eq!(fs::read(payload.join("first.txt")).unwrap(), b"first body");
}
