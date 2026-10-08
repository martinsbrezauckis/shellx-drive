use std::fs;

use super::*;

#[cfg(target_os = "windows")]
#[test]
fn long_local_root_preserves_private_staging_and_owned_batch_cleanup() {
    use std::os::windows::ffi::OsStrExt;

    let directory = tempfile::tempdir().unwrap();
    let mut parent = directory.path().to_path_buf();
    while parent.as_os_str().encode_wide().count() < 300 {
        parent.push("legal-nested-local-root-segment");
    }
    fs::create_dir_all(&parent).unwrap();
    let root = parent.join("Drive");
    fs::create_dir(&root).unwrap();
    let untouched = parent.join("unrelated.txt");
    fs::write(&untouched, b"preserve unrelated sibling").unwrap();

    for (kind, staging) in [
        ("upload", upload_staging_root(&root).unwrap()),
        ("download", download_staging_root(&root).unwrap()),
        ("restore", restore_staging_root(&root).unwrap()),
    ] {
        assert!(staging.as_os_str().encode_wide().count() > 260);
        let area = initialize_owned_staging_root(&root, &staging, kind).unwrap();
        private_staging::validate_private_directory(area.root()).unwrap();
        let batch = area.create_batch(1).unwrap();
        private_staging::validate_private_directory(&batch).unwrap();
        let body = batch.join("body.txt");
        fs::write(&body, b"owned temporary body").unwrap();
        assert_eq!(fs::read(&body).unwrap(), b"owned temporary body");
        area.remove_batch(&batch).unwrap();
        assert!(!batch.exists());
        area.validate_root().unwrap();
    }
    assert_eq!(fs::read(&untouched).unwrap(), b"preserve unrelated sibling");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_api_path_encoding_keeps_absolute_namespaces_and_rejects_traversal() {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};

    for (input, expected) in [
        (r"C:\parent\child", r"\\?\C:\parent\child"),
        (r"C:/parent/./child", r"\\?\C:\parent\child"),
        (r"\\server\share\child", r"\\?\UNC\server\share\child"),
        (r"\\?\C:\parent\child", r"\\?\C:\parent\child"),
        (r"\\?\UNC\server\share\child", r"\\?\UNC\server\share\child"),
    ] {
        let wide = windows_absolute_path_wide(Path::new(input)).unwrap();
        assert_eq!(wide.last(), Some(&0));
        assert_eq!(
            OsString::from_wide(&wide[..wide.len() - 1]),
            OsStr::new(expected)
        );
    }
    for input in [
        r"relative\child",
        r"C:child",
        r"C:\parent\..\child",
        r"\\.\C:\child",
    ] {
        assert!(windows_absolute_path_wide(Path::new(input)).is_err());
    }
    let nul = OsString::from_wide(&[b'C' as u16, b':' as u16, b'\\' as u16, 0, b'x' as u16]);
    assert!(windows_absolute_path_wide(Path::new(&nul)).is_err());
}

#[test]
fn staging_roots_are_namespaced_siblings() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).unwrap();

    for (prefix, staging) in [
        (RESTORE_STAGING_DIR, restore_staging_root(&root).unwrap()),
        (DOWNLOAD_STAGING_DIR, download_staging_root(&root).unwrap()),
        (UPLOAD_STAGING_DIR, upload_staging_root(&root).unwrap()),
    ] {
        assert_eq!(staging.parent(), root.parent());
        assert!(!staging.starts_with(&root));
        let name = staging.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with(&format!("{prefix}-")));
        assert_eq!(name.len(), prefix.len() + 1 + STAGING_NAMESPACE_HEX_CHARS);
    }
}

#[test]
fn sibling_pairs_have_independent_owned_staging_roots() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("Drive A");
    let second = directory.path().join("Drive B");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();

    for (kind, first_staging, second_staging) in [
        (
            "restore",
            restore_staging_root(&first).unwrap(),
            restore_staging_root(&second).unwrap(),
        ),
        (
            "download",
            download_staging_root(&first).unwrap(),
            download_staging_root(&second).unwrap(),
        ),
        (
            "upload",
            upload_staging_root(&first).unwrap(),
            upload_staging_root(&second).unwrap(),
        ),
    ] {
        assert_ne!(first_staging, second_staging);
        let first_area = initialize_owned_staging_root(&first, &first_staging, kind).unwrap();
        let second_area = initialize_owned_staging_root(&second, &second_staging, kind).unwrap();
        assert_ne!(first_area.root(), second_area.root());
        first_area.validate_root().unwrap();
        second_area.validate_root().unwrap();
    }
}
