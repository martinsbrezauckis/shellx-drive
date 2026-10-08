use std::{
    io::Write as _,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
};

use super::{
    ensure_cache_directory, ensure_cache_root, unix_test_support::private_tempdir,
    SafeDownloadTarget, SafeLocalSnapshot,
};

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn created_cache_directories_are_owner_only() {
    let temp = private_tempdir();
    let root = temp.path().join("cache");
    let cache = ensure_cache_root(&root).unwrap();
    let content = ensure_cache_directory(&cache, Path::new("workspaces/id/content")).unwrap();

    assert_eq!(std::fs::metadata(root).unwrap().mode() & 0o777, 0o700);
    assert_eq!(std::fs::metadata(content).unwrap().mode() & 0o777, 0o700);
}

#[test]
fn created_cache_root_remains_valid_under_a_setgid_parent() {
    let temp = private_tempdir();
    let parent = temp.path().join("setgid-parent");
    std::fs::create_dir(&parent).unwrap();
    set_mode(&parent, 0o2700);
    let root = parent.join("cache");

    ensure_cache_root(&root).unwrap();

    assert_eq!(std::fs::metadata(root).unwrap().mode() & 0o777, 0o700);
}

#[test]
fn non_private_existing_cache_root_modes_are_rejected_without_repair() {
    let temp = private_tempdir();
    for mode in [0o777, 0o600, 0o1700, 0o4700] {
        let root = temp.path().join(format!("cache-{mode:o}"));
        std::fs::create_dir(&root).unwrap();
        set_mode(&root, mode);

        let error = ensure_cache_root(&root)
            .err()
            .expect("unsafe root rejected");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::metadata(&root).unwrap().mode() & 0o7777, mode);
    }
}

#[test]
fn owner_only_existing_setgid_root_is_accepted_without_repair() {
    let temp = private_tempdir();
    let root = temp.path().join("cache-setgid");
    std::fs::create_dir(&root).unwrap();
    set_mode(&root, 0o2700);

    ensure_cache_root(&root).unwrap();

    assert_eq!(std::fs::metadata(root).unwrap().mode() & 0o7777, 0o2700);
}

#[test]
fn permissive_existing_descendant_is_rejected_before_use() {
    let temp = private_tempdir();
    let root = temp.path().join("cache");
    let cache = ensure_cache_root(&root).unwrap();
    let content = ensure_cache_directory(&cache, Path::new("workspaces/id/content")).unwrap();
    set_mode(&content, 0o777);

    assert!(cache.regular_file_names(&content, 16, 1024).is_err());
    assert!(SafeDownloadTarget::begin(&cache, &content.join("remote-id")).is_err());
}

#[test]
fn owner_created_readable_file_remains_valid_but_peer_write_is_rejected() {
    let temp = private_tempdir();
    let root = temp.path().join("cache");
    let cache = ensure_cache_root(&root).unwrap();
    let content = ensure_cache_directory(&cache, Path::new("workspaces/id/content")).unwrap();
    let local = content.join("local.txt");
    std::fs::write(&local, b"ordinary editor output").unwrap();
    set_mode(&local, 0o644);

    assert!(SafeLocalSnapshot::open(&cache, &local, 1024).is_ok());

    set_mode(&local, 0o664);
    let error = SafeLocalSnapshot::open(&cache, &local, 1024)
        .err()
        .expect("peer-writable input rejected");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn hard_linked_input_is_rejected() {
    let temp = private_tempdir();
    let root = temp.path().join("cache");
    let cache = ensure_cache_root(&root).unwrap();
    let content = ensure_cache_directory(&cache, Path::new("workspaces/id/content")).unwrap();
    let local = content.join("local.txt");
    let alias = content.join("alias.txt");
    std::fs::write(&local, b"linked content").unwrap();
    set_mode(&local, 0o644);
    std::fs::hard_link(&local, &alias).unwrap();

    assert_eq!(std::fs::metadata(&local).unwrap().nlink(), 2);
    let error = SafeLocalSnapshot::open(&cache, &local, 1024)
        .err()
        .expect("hard-linked input rejected");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn owner_private_publication_still_commits() {
    let temp = private_tempdir();
    let root = temp.path().join("cache");
    let cache = ensure_cache_root(&root).unwrap();
    let content = ensure_cache_directory(&cache, Path::new("workspaces/id/content")).unwrap();
    let destination = content.join("remote-id");
    let mut target = SafeDownloadTarget::begin(&cache, &destination).unwrap();
    target.file_mut().write_all(b"verified remote").unwrap();
    target.commit().unwrap();

    assert_eq!(std::fs::read(&destination).unwrap(), b"verified remote");
    assert_eq!(
        std::fs::metadata(destination).unwrap().mode() & 0o777,
        0o600
    );
}

#[cfg(target_os = "macos")]
#[test]
fn cache_test_fixture_is_canonical_and_accepted() {
    let temp = private_tempdir();
    assert_eq!(
        std::fs::canonicalize(temp.path()).unwrap(),
        temp.path(),
        "the macOS fixture must not retain the /var symlink alias"
    );
    assert!(ensure_cache_root(&temp.path().join("cache")).is_ok());
}
