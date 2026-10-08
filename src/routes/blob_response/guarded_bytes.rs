//! Bounded delivery for response bodies that must first be encoded in memory.
//!
//! The producer owns the encoded allocation while the body retains its admission
//! guards through EOF or cancellation. A small channel and deadlines prevent a
//! slow or abandoned client from retaining bytes or permits forever.

use std::time::Duration;

use axum::{body::Bytes, response::Response};
use tokio::sync::mpsc;

mod body;
#[cfg(test)]
mod tests;

use body::GuardedBodyState;
use producer::produce_bounded_bytes;

mod producer;
mod receiver;

pub(crate) use receiver::guard_blob_receiver_with_total_deadline;
use receiver::guarded_receiver_with_total_deadline;

use super::{
    BLOB_STREAM_BACKPRESSURE_TIMEOUT, BLOB_STREAM_CHANNEL_CAPACITY, BLOB_STREAM_CHUNK_BYTES,
};

pub(crate) fn guard_bounded_bytes_response_with_total_deadline<G>(
    response: Response,
    encoded: Vec<u8>,
    guard: G,
    total_timeout: Duration,
) -> Response
where
    G: Send + 'static,
{
    guard_bounded_bytes_response_with_timeout(
        response,
        encoded,
        guard,
        BLOB_STREAM_BACKPRESSURE_TIMEOUT,
        total_timeout,
    )
}

fn guard_bounded_bytes_response_with_timeout<G>(
    response: Response,
    encoded: Vec<u8>,
    guard: G,
    body_hold_timeout: Duration,
    total_timeout: Duration,
) -> Response
where
    G: Send + 'static,
{
    let (parts, _) = response.into_parts();
    let (sender, receiver) = mpsc::channel(BLOB_STREAM_CHANNEL_CAPACITY);
    let (body, state) = guarded_receiver_with_total_deadline(receiver, guard, total_timeout);
    tokio::spawn(produce_bounded_bytes(
        Bytes::from(encoded),
        sender,
        state,
        body_hold_timeout,
    ));
    Response::from_parts(parts, body)
}
