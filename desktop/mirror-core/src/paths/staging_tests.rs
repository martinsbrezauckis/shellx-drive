use std::fs;

use super::*;

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
