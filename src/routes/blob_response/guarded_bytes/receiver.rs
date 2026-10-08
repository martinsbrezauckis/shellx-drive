//! Guarded body receiver and its terminal publication deadlines.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::body::{Body, Bytes};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_stream::wrappers::ReceiverStream;

use super::{
    body::{GuardedBodyState, GuardedReceiverStream},
    BLOB_STREAM_BACKPRESSURE_TIMEOUT,
};

pub(crate) fn guard_blob_receiver_with_total_deadline<G>(
    receiver: mpsc::Receiver<Result<Bytes, std::io::Error>>,
    guard: G,
    total_timeout: Duration,
    producer_done: oneshot::Receiver<()>,
) -> Body
where
    G: Send + 'static,
{
    let (body, state) = guarded_receiver_with_total_deadline(receiver, guard, total_timeout);
    // A short body can be fully queued before the HTTP client polls it. Once
    // its producer exits, release that queue and permit after delivery stalls.
    let tail_state = Arc::downgrade(&state);
    let mut done_rx = state.lock().unwrap().done.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            _ = producer_done => {
                let mut wait = BLOB_STREAM_BACKPRESSURE_TIMEOUT;
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {
                            let Some(state) = tail_state.upgrade() else { break; };
                            let mut state = state.lock().unwrap();
                            let idle = tokio::time::Instant::now()
                                .saturating_duration_since(state.last_progress);
                            if idle >= BLOB_STREAM_BACKPRESSURE_TIMEOUT {
                                state.close();
                                break;
                            }
                            wait = BLOB_STREAM_BACKPRESSURE_TIMEOUT - idle;
                        }
                        _ = done_rx.changed() => break,
                    }
                }
            }
            _ = done_rx.changed() => {}
        }
    });
    body
}
pub(super) fn guarded_receiver_with_total_deadline<G>(
    receiver: mpsc::Receiver<Result<Bytes, std::io::Error>>,
    guard: G,
    total_timeout: Duration,
) -> (Body, Arc<Mutex<GuardedBodyState<G>>>)
where
    G: Send + 'static,
{
    let (done, mut done_rx) = watch::channel(false);
    let state = Arc::new(Mutex::new(GuardedBodyState {
        receiver: Some(ReceiverStream::new(receiver)),
        guard: Some(guard),
        done,
        last_progress: tokio::time::Instant::now(),
        waker: None,
    }));
    let total_state = Arc::downgrade(&state);
    let total_deadline = tokio::time::Instant::now() + total_timeout;
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep_until(total_deadline) => {
                if let Some(state) = total_state.upgrade() {
                    state.lock().unwrap().close();
                }
            }
            _ = done_rx.changed() => {}
        }
    });
    (
        Body::from_stream(GuardedReceiverStream {
            state: state.clone(),
        }),
        state,
    )
}
