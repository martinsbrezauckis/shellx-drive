use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use axum::body::to_bytes;
use axum::http::header;

use super::*;

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn metadata_response_keeps_its_checked_bytes_and_guard_until_delivery_stops() {
    let rejected = bounded_metadata_response(
        Body::empty().into_response(),
        vec![b'x'; MAX_PUBLIC_SHARE_METADATA_BYTES + 1],
        (),
    );
    assert!(matches!(rejected, Err(ApiError::PayloadTooLarge(_))));

    let encoded = vec![b'x'; 1024];
    let dropped = Arc::new(AtomicBool::new(false));
    let response = bounded_metadata_response(
        Body::empty().into_response(),
        encoded.clone(),
        DropFlag(dropped.clone()),
    )
    .unwrap();
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert_eq!(
        response.headers()[header::CONTENT_LENGTH],
        encoded.len().to_string()
    );
    tokio::task::yield_now().await;
    assert!(!dropped.load(Ordering::SeqCst));
    drop(response);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !dropped.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let response =
        bounded_metadata_response(Body::empty().into_response(), encoded.clone(), ()).unwrap();
    assert_eq!(
        to_bytes(response.into_body(), MAX_PUBLIC_SHARE_METADATA_BYTES)
            .await
            .unwrap(),
        encoded
    );
}
