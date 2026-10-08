use super::*;

#[test]
fn exclusive_persistent_upload_lock_is_private_and_reacquirable() {
    let temp = tempfile::tempdir().unwrap();
    crate::fs_private::set_dir_private(temp.path()).unwrap();
    let session_id = uuid::Uuid::new_v4().to_string();
    let file = UploadSessionLock::acquire(temp.path(), &session_id).unwrap();
    file.verify_private_handles().unwrap();
    assert!(
        UploadSessionLock::acquire(temp.path(), &session_id).is_err(),
        "a second owner must not acquire the upload lock"
    );

    drop(file);
    let replacement = UploadSessionLock::acquire(temp.path(), &session_id).unwrap();
    replacement.verify_private_handles().unwrap();
}
