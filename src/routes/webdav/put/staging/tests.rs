use std::{future::Future, pin::Pin, task::Poll};

use super::DavStagingFile;

#[test]
fn cancelled_creation_cleans_up_even_when_the_blocking_worker_runs_later() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        started_rx.await.unwrap();
        let mut creation = Box::pin(DavStagingFile::create_in_directory(
            directory.path().to_path_buf(),
        ));
        std::future::poll_fn(|cx| {
            assert!(matches!(Pin::new(&mut creation).poll(cx), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        // Dropping the request future detaches its already-queued blocking task.
        drop(creation);
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        // The single blocking thread executes this barrier after the creator.
        tokio::task::spawn_blocking(|| ()).await.unwrap();
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    });
}

#[tokio::test]
async fn normal_staging_retains_the_file_until_its_owner_drops() {
    let directory = tempfile::tempdir().unwrap();
    let mut staging = DavStagingFile::create_in_directory(directory.path().to_path_buf())
        .await
        .unwrap();
    let path = staging.path().to_path_buf();
    assert!(path.exists());
    let file = staging.take_open_file();
    assert!(file.metadata().unwrap().is_file());
    drop(file);
    drop(staging);
    assert!(!path.exists());
}

#[test]
fn privacy_failure_cleans_up_but_create_new_failure_preserves_existing_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private.part");
    assert!(super::create_private_file_with(&path, |_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "privacy",
        ))
    })
    .is_err());
    assert!(!path.exists());
    std::fs::write(&path, b"existing").unwrap();
    assert!(super::create_private_file(&path).is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"existing");
}
