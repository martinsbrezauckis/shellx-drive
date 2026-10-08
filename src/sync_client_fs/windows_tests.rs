use std::{
    fs,
    io::Write,
    os::windows::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, READ_CONTROL, WRITE_DAC,
};

use super::{ensure_cache_directory, ensure_cache_root, SafeDownloadTarget, SafeLocalSnapshot};

fn open_directory_for_acl_check(path: PathBuf) -> fs::File {
    let mut options = fs::OpenOptions::new();
    options
        .access_mode(READ_CONTROL | WRITE_DAC)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    options.open(path).unwrap()
}

#[test]
fn download_target_pins_its_parent_until_verified_replace() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let cache = ensure_cache_root(&root).unwrap();
    let content = ensure_cache_directory(&cache, Path::new("workspaces/id/content")).unwrap();
    assert!(fs::rename(temp.path(), temp.path().with_extension("moved")).is_err());
    crate::fs_private::verify_private_dir_handle(&open_directory_for_acl_check(root.clone()))
        .unwrap();
    crate::fs_private::verify_private_dir_handle(&open_directory_for_acl_check(content.clone()))
        .unwrap();
    let destination = content.join("remote-id");
    std::fs::write(&destination, b"old").unwrap();
    let mut target = SafeDownloadTarget::begin(&cache, &destination).unwrap();
    assert!(std::fs::rename(&content, root.join("substituted-content")).is_err());
    target.file_mut().write_all(b"verified remote").unwrap();
    target.commit().unwrap();

    assert_eq!(std::fs::read(destination).unwrap(), b"verified remote");
    let final_file = fs::File::open(content.join("remote-id")).unwrap();
    crate::fs_private::verify_private_file_handle(&final_file).unwrap();
}

#[test]
fn create_only_rename_moves_source_and_preserves_both_files_on_collision() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let cache = ensure_cache_root(&root).unwrap();
    let content = ensure_cache_directory(&cache, Path::new("workspaces/id/content")).unwrap();
    let source = content.join("new.txt");
    let destination = content.join("remote-id");
    fs::write(&source, b"new local").unwrap();
    crate::fs_private::set_file_private(&source).unwrap();
    cache.rename_new(&source, &destination).unwrap();
    assert!(!source.exists());
    assert_eq!(cache.regular_file_len(&destination).unwrap(), 9);
    assert_eq!(fs::read(&destination).unwrap(), b"new local");
    fs::write(&source, b"later local").unwrap();
    crate::fs_private::set_file_private(&source).unwrap();
    let error = cache.rename_new(&source, &destination).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&source).unwrap(), b"later local");
    assert_eq!(fs::read(&destination).unwrap(), b"new local");
}

#[test]
fn permissive_existing_cache_objects_are_rejected_without_repair() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let cache = ensure_cache_root(&root).unwrap();
    let content = ensure_cache_directory(&cache, Path::new("workspaces/id/content")).unwrap();

    let root_handle = open_directory_for_acl_check(root.clone());
    crate::fs_private::grant_world_write_for_test(&root_handle, true).unwrap();
    drop(cache);
    assert!(ensure_cache_root(&root).is_err());
    assert!(crate::fs_private::verify_private_dir_handle(&root_handle).is_err());

    crate::fs_private::apply_private_dir_handle(&root_handle).unwrap();
    let cache = ensure_cache_root(&root).unwrap();
    let content_handle = open_directory_for_acl_check(content.clone());
    crate::fs_private::grant_world_write_for_test(&content_handle, true).unwrap();
    assert!(cache.regular_file_names(&content, 16, 1024).is_err());
    assert!(crate::fs_private::verify_private_dir_handle(&content_handle).is_err());
    crate::fs_private::apply_private_dir_handle(&content_handle).unwrap();

    let existing = content.join("existing-file");
    std::fs::write(&existing, b"potentially tampered").unwrap();
    crate::fs_private::set_file_private(&existing).unwrap();
    let mut file_options = fs::OpenOptions::new();
    file_options
        .access_mode(READ_CONTROL | WRITE_DAC)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let existing_handle = file_options.open(&existing).unwrap();
    crate::fs_private::grant_world_write_for_test(&existing_handle, false).unwrap();

    assert!(SafeLocalSnapshot::open(&cache, &existing, 1024).is_err());
    assert!(crate::fs_private::verify_private_file_handle(&existing_handle).is_err());
}
