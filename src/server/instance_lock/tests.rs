use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

use super::*;

#[test]
fn private_windows_lock_starts_and_excludes_a_second_owner() {
    let temp = tempfile::tempdir().unwrap();
    crate::fs_private::set_dir_private(temp.path()).unwrap();

    let first = acquire(temp.path()).unwrap();
    crate::fs_private::verify_private_file_handle(&first._file).unwrap();
    let error = match acquire(temp.path()) {
        Ok(_) => panic!("a second owner acquired the instance lock"),
        Err(error) => error,
    };
    assert_eq!(error.raw_os_error(), Some(ERROR_SHARING_VIOLATION as i32));

    drop(first);
    let replacement = acquire(temp.path()).unwrap();
    crate::fs_private::verify_private_file_handle(&replacement._file).unwrap();
}
