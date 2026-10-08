use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use axum::body::{to_bytes, Body};

use super::*;

mod deadline;

mod stored_receiver;

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn guard_survives_while_the_bounded_channel_is_backpressured() {
    let dropped = Arc::new(AtomicBool::new(false));
    let bytes = vec![0; BLOB_STREAM_CHUNK_BYTES * (BLOB_STREAM_CHANNEL_CAPACITY + 2)];
    let response = guard_bounded_bytes_response_with_total_deadline(
        Response::new(Body::empty()),
        bytes,
        DropFlag(dropped.clone()),
        Duration::from_secs(10 * 60),
    );
    tokio::task::yield_now().await;
    assert!(!dropped.load(Ordering::SeqCst));
    drop(response);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !dropped.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn small_unread_body_keeps_guard_until_drop_or_deadline() {
    let dropped = Arc::new(AtomicBool::new(false));
    let response = guard_bounded_bytes_response_with_timeout(
        Response::new(Body::empty()),
        vec![0; 1024],
        DropFlag(dropped.clone()),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    tokio::task::yield_now().await;
    assert!(!dropped.load(Ordering::SeqCst));
    drop(response);
    assert!(dropped.load(Ordering::SeqCst));

    let dropped = Arc::new(AtomicBool::new(false));
    let response = guard_bounded_bytes_response_with_timeout(
        Response::new(Body::empty()),
        vec![7; 1024],
        DropFlag(dropped.clone()),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        vec![7; 1024]
    );
    assert!(dropped.load(Ordering::SeqCst));

    let dropped = Arc::new(AtomicBool::new(false));
    let unread_response = guard_bounded_bytes_response_with_timeout(
        Response::new(Body::empty()),
        vec![0; 1024],
        DropFlag(dropped.clone()),
        Duration::from_millis(10),
        Duration::from_secs(1),
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while !dropped.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(to_bytes(unread_response.into_body(), 1024)
        .await
        .unwrap()
        .is_empty());
}
