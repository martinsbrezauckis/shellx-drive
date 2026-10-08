use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::PathBuf,
};

pub(crate) fn private_tempdir() -> tempfile::TempDir {
    let home = canonical_current_user_home();
    let directory = tempfile::Builder::new()
        .prefix(".shellx-drive-sync-test-")
        .tempdir_in(home)
        .expect("create sync cache test fixture beneath the canonical home directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("make sync cache test fixture owner-only");
    assert_eq!(
        fs::canonicalize(directory.path()).expect("canonicalize sync cache test fixture"),
        directory.path(),
        "sync cache test fixture must not use a symlink alias"
    );
    directory
}

fn canonical_current_user_home() -> PathBuf {
    let home = std::env::var_os("HOME").expect("HOME must be set for Unix sync cache tests");
    let home = fs::canonicalize(home).expect("canonicalize HOME for Unix sync cache tests");
    let metadata = fs::metadata(&home).expect("read canonical HOME metadata");
    assert!(metadata.is_dir(), "canonical HOME must be a directory");
    assert_eq!(
        metadata.uid(),
        unsafe { libc::geteuid() },
        "canonical HOME must be owned by the current user"
    );
    home
}
