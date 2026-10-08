use std::{fs, os::unix::fs::OpenOptionsExt, path::Path};

use shellx_drive_desktop_core::{
    DirectoryIdentity, DirectoryIdentityPlatform, PairMarker, PairMarkerDisposition,
};

use super::{marker::PAIR_MARKER_FILE, test_fixture_directory, UnixRootGuard};

mod child_root;
mod mutations;
mod planning;
mod restore_publication;

#[cfg(target_os = "macos")]
mod macos_mutations;

#[test]
fn unix_identity_rejects_a_legacy_windows_record() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).unwrap();
    let guard = UnixRootGuard::acquire(&root, None).unwrap();
    assert_eq!(guard.identity().platform, DirectoryIdentityPlatform::Unix);
    assert!(UnixRootGuard::acquire(&root, Some(&DirectoryIdentity::windows(7, [3; 16]))).is_err());
}
#[test]
fn unix_root_refuses_a_symlink() {
    let directory = test_fixture_directory();
    let real = directory.path().join("real");
    let link = directory.path().join("link");
    fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(UnixRootGuard::acquire(&link, None).is_err());
}

#[test]
fn root_identity_revalidation_rejects_a_replaced_configured_path() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    let displaced = directory.path().join("Drive-displaced");
    fs::create_dir(&root).unwrap();
    let guard = UnixRootGuard::acquire(&root, None).unwrap();

    fs::rename(&root, &displaced).unwrap();
    fs::create_dir(&root).unwrap();

    assert!(guard.ensure_identity("test replacement").is_err());
}

#[test]
fn no_replace_move_rejects_a_hardlinked_source() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).unwrap();
    let source = root.join("tracked.txt");
    fs::write(&source, b"tracked").unwrap();
    fs::hard_link(&source, root.join("alias.txt")).unwrap();
    assert!(UnixRootGuard::acquire(&root, None).is_err());
    assert_eq!(fs::read(&source).unwrap(), b"tracked");
    assert!(!root.join("moved.txt").exists());
}

#[test]
fn atomic_new_publication_keeps_existing_staging_on_collision() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    let staging = directory.path().join("private");
    fs::create_dir(&root).unwrap();
    shellx_drive_desktop_core::ensure_private_staging_directory(&staging).unwrap();
    let staged = staging.join("body");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)
        .unwrap();
    use std::io::Write;
    file.write_all(b"new body").unwrap();
    drop(file);

    let guard = UnixRootGuard::acquire(&root, None).unwrap();
    guard
        .publish_staged_file(&staged, Path::new("report.txt"), false)
        .unwrap();
    assert_eq!(fs::read(root.join("report.txt")).unwrap(), b"new body");
    assert!(!staged.exists());

    let staged_collision = staging.join("collision");
    let mut collision = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged_collision)
        .unwrap();
    collision.write_all(b"retain me").unwrap();
    drop(collision);
    assert!(guard
        .publish_staged_file(&staged_collision, Path::new("report.txt"), false)
        .is_err());
    assert_eq!(fs::read(&staged_collision).unwrap(), b"retain me");
}

#[test]
fn marker_is_exact_and_removal_preserves_other_root_content() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).unwrap();
    let guard = UnixRootGuard::acquire(&root, None).unwrap();
    let marker = PairMarker {
        schema_version: 2,
        workspace_id: "workspace".to_string(),
        remote_root_id: Some("folder".to_string()),
        server_url: "https://drive.example.test".to_string(),
        local_root_identity: Some(guard.identity().clone()),
    };

    assert_eq!(
        guard.write_or_recognize_pair_marker(&marker).unwrap(),
        PairMarkerDisposition::Created
    );
    guard.require_exact_pair_marker(&marker).unwrap();
    assert_eq!(
        guard.write_or_recognize_pair_marker(&marker).unwrap(),
        PairMarkerDisposition::ExistingIdentical
    );
    fs::write(root.join("kept.txt"), b"user bytes").unwrap();
    assert!(guard.remove_exact_pair_marker(&marker).unwrap());
    assert_eq!(fs::read(root.join("kept.txt")).unwrap(), b"user bytes");
    assert!(!root.join(PAIR_MARKER_FILE).exists());
}

#[test]
fn directory_creation_reopens_each_component_without_following_links() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).unwrap();
    let guard = UnixRootGuard::acquire(&root, None).unwrap();
    guard
        .ensure_directory(Path::new("Shared with me/Avery/Reports"))
        .unwrap();
    assert!(root.join("Shared with me/Avery/Reports").is_dir());

    let outside = directory.path().join("outside");
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("unsafe")).unwrap();
    assert!(guard.ensure_directory(Path::new("unsafe/child")).is_err());
    assert!(!outside.join("child").exists());
}
