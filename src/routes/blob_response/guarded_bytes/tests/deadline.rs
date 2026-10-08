use super::*;

#[tokio::test]
async fn total_deadline_discards_an_inflight_body() {
    let dropped = Arc::new(AtomicBool::new(false));
    let response = guard_bounded_bytes_response_with_timeout(
        Response::new(Body::empty()),
        vec![1; BLOB_STREAM_CHUNK_BYTES * 100],
        DropFlag(dropped.clone()),
        Duration::from_secs(1),
        Duration::from_millis(20),
    );
    let body = response.into_body();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !dropped.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("total deadline must release the in-flight body guard");
    assert!(dropped.load(Ordering::SeqCst));
    assert!(to_bytes(body, usize::MAX).await.unwrap().is_empty());
}
