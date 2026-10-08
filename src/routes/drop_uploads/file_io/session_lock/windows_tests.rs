use super::*;

#[test]
fn exclusive_drop_upload_lock_is_private_and_reacquirable() {
    let temp = tempfile::tempdir().unwrap();
    crate::fs_private::set_dir_private(temp.path()).unwrap();
    let session_id = "a".repeat(64);
    let first = SessionFileLock::acquire(temp.path(), &session_id).unwrap();
    first._lock.verify_private_handles().unwrap();

    assert!(matches!(
        SessionFileLock::acquire(temp.path(), &session_id),
        Err(crate::error::ApiError::Conflict)
    ));

    drop(first);
    let replacement = SessionFileLock::acquire(temp.path(), &session_id).unwrap();
    replacement._lock.verify_private_handles().unwrap();
}
