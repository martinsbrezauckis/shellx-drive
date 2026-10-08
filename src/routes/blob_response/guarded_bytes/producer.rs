use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::body::Bytes;
use tokio::sync::mpsc;

use super::{GuardedBodyState, BLOB_STREAM_BACKPRESSURE_TIMEOUT, BLOB_STREAM_CHUNK_BYTES};

pub(super) async fn produce_bounded_bytes<G>(
    mut encoded: Bytes,
    sender: mpsc::Sender<Result<Bytes, std::io::Error>>,
    state: Arc<Mutex<GuardedBodyState<G>>>,
    body_hold_timeout: Duration,
) where
    G: Send + 'static,
{
    while !encoded.is_empty() {
        let chunk = encoded.split_to(encoded.len().min(BLOB_STREAM_CHUNK_BYTES));
        match tokio::time::timeout(BLOB_STREAM_BACKPRESSURE_TIMEOUT, sender.send(Ok(chunk))).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => break,
        }
    }
    // The producer can finish while the receiver still holds queued bytes.
    // Keep the permit until EOF/drop, but discard both queued bytes and permit
    // after a bounded period if the client never polls the final body.
    let mut done_rx = state.lock().unwrap().done.subscribe();
    let tail_state = Arc::downgrade(&state);
    tokio::spawn(async move {
        if *done_rx.borrow() {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(body_hold_timeout) => {
                if let Some(state) = tail_state.upgrade() {
                    state.lock().unwrap().close();
                }
            }
            _ = done_rx.changed() => {}
        }
    });
}
