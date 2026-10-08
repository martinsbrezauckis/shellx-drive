use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use axum::body::Bytes;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_stream::{wrappers::ReceiverStream, Stream};

pub(super) struct GuardedBodyState<G> {
    pub(super) receiver: Option<ReceiverStream<Result<Bytes, std::io::Error>>>,
    pub(super) guard: Option<G>,
    pub(super) done: watch::Sender<bool>,
    pub(super) last_progress: Instant,
    pub(super) waker: Option<Waker>,
}

impl<G> GuardedBodyState<G> {
    pub(super) fn close(&mut self) {
        self.receiver.take();
        self.guard.take();
        self.done.send_replace(true);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

pub(super) struct GuardedReceiverStream<G> {
    pub(super) state: Arc<Mutex<GuardedBodyState<G>>>,
}

impl<G> Stream for GuardedReceiverStream<G> {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut state = self.state.lock().unwrap();
        state.waker = Some(cx.waker().clone());
        let result = match state.receiver.as_mut() {
            Some(receiver) => Pin::new(receiver).poll_next(cx),
            None => Poll::Ready(None),
        };
        if matches!(result, Poll::Ready(Some(_))) {
            state.last_progress = Instant::now();
        }
        if matches!(result, Poll::Ready(None)) {
            state.close();
        }
        result
    }
}

impl<G> Drop for GuardedReceiverStream<G> {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        state.close();
    }
}
