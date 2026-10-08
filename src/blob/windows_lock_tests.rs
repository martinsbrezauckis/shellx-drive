use std::{
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::Duration,
};

use super::*;

const BLOCK_CHECK: Duration = Duration::from_millis(200);
const COMPLETION_WAIT: Duration = Duration::from_secs(5);

#[test]
fn lifecycle_lock_is_private_shared_and_exclusive() {
    let temp = tempfile::tempdir().unwrap();
    crate::fs_private::set_dir_private(temp.path()).unwrap();
    let path = temp.path().to_path_buf();

    let first = BlobLifecycleLock::acquire_shared(&path).unwrap();
    let second = BlobLifecycleLock::acquire_shared(&path).unwrap();
    crate::fs_private::verify_private_file_handle(&first.file).unwrap();

    let (started_tx, started_rx) = mpsc::channel();
    let (exclusive_tx, exclusive_rx) = mpsc::channel();
    let exclusive_path = path.clone();
    let exclusive_thread = thread::spawn(move || {
        started_tx.send(()).unwrap();
        exclusive_tx.send(BlobLifecycleLock::acquire_exclusive(&exclusive_path))
    });
    started_rx.recv_timeout(COMPLETION_WAIT).unwrap();
    assert!(matches!(
        exclusive_rx.recv_timeout(BLOCK_CHECK),
        Err(RecvTimeoutError::Timeout)
    ));

    drop(first);
    drop(second);
    let exclusive = exclusive_rx.recv_timeout(COMPLETION_WAIT).unwrap().unwrap();
    exclusive_thread.join().unwrap().unwrap();
    crate::fs_private::verify_private_file_handle(&exclusive.file).unwrap();

    let (started_tx, started_rx) = mpsc::channel();
    let (shared_tx, shared_rx) = mpsc::channel();
    let shared_thread = thread::spawn(move || {
        started_tx.send(()).unwrap();
        shared_tx.send(BlobLifecycleLock::acquire_shared(&path))
    });
    started_rx.recv_timeout(COMPLETION_WAIT).unwrap();
    assert!(matches!(
        shared_rx.recv_timeout(BLOCK_CHECK),
        Err(RecvTimeoutError::Timeout)
    ));

    drop(exclusive);
    let shared = shared_rx.recv_timeout(COMPLETION_WAIT).unwrap().unwrap();
    shared_thread.join().unwrap().unwrap();
    crate::fs_private::verify_private_file_handle(&shared.file).unwrap();
}
