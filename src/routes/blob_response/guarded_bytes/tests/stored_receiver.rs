use http_body_util::BodyExt as _;
use tokio::sync::oneshot;

use super::*;

#[tokio::test(start_paused = true)]
async fn stored_blob_receiver_total_deadline_cuts_off_a_trickling_body() {
    let dropped = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel(BLOB_STREAM_CHANNEL_CAPACITY);
    let (_producer_done_tx, producer_done_rx) = oneshot::channel();
    let mut body = guard_blob_receiver_with_total_deadline(
        receiver,
        DropFlag(dropped.clone()),
        Duration::from_secs(30),
        producer_done_rx,
    );

    for _ in 0..3 {
        sender.send(Ok(Bytes::from_static(b"chunk"))).await.unwrap();
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            Bytes::from_static(b"chunk")
        );
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
    }
    assert!(dropped.load(Ordering::SeqCst));
    assert!(body.frame().await.is_none());
    assert!(sender.is_closed());
}

#[tokio::test(start_paused = true)]
async fn stored_blob_unread_queued_body_releases_guard_after_producer_finishes() {
    let dropped = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel(BLOB_STREAM_CHANNEL_CAPACITY);
    let (producer_done_tx, producer_done_rx) = oneshot::channel();
    let mut body = guard_blob_receiver_with_total_deadline(
        receiver,
        DropFlag(dropped.clone()),
        Duration::from_secs(5 * 60 * 60),
        producer_done_rx,
    );
    sender
        .send(Ok(Bytes::from_static(b"queued")))
        .await
        .unwrap();
    drop(sender);
    producer_done_tx.send(()).unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(BLOB_STREAM_BACKPRESSURE_TIMEOUT).await;
    tokio::task::yield_now().await;
    assert!(dropped.load(Ordering::SeqCst));
    assert!(body.frame().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn stored_blob_queued_tail_survives_steady_delivery_after_producer_finishes() {
    let dropped = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel(BLOB_STREAM_CHANNEL_CAPACITY);
    let (producer_done_tx, producer_done_rx) = oneshot::channel();
    let mut body = guard_blob_receiver_with_total_deadline(
        receiver,
        DropFlag(dropped.clone()),
        Duration::from_secs(110),
        producer_done_rx,
    );
    for _ in 0..BLOB_STREAM_CHANNEL_CAPACITY {
        sender.send(Ok(Bytes::from_static(b"tail"))).await.unwrap();
    }
    drop(sender);
    producer_done_tx.send(()).unwrap();
    tokio::task::yield_now().await;

    for index in 0..BLOB_STREAM_CHANNEL_CAPACITY {
        if index > 0 {
            tokio::time::advance(Duration::from_secs(12)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            Bytes::from_static(b"tail")
        );
        assert!(!dropped.load(Ordering::SeqCst));
    }
    assert!(body.frame().await.is_none());
    assert!(dropped.load(Ordering::SeqCst));
}
