//! Absolute delivery bounds shared by the ZIP receiver and blocking producer.

use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

use axum::body::{Body, Bytes};
use tokio::sync::{mpsc, oneshot};

use super::{write_archive, ArchiveEntry, ArchiveEntryRevalidator, ArchiveProducerPermit};
use crate::routes::blob_response::guard_blob_receiver_with_total_deadline;

const ARCHIVE_BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(30);
const ARCHIVE_BACKPRESSURE_RETRY: Duration = Duration::from_millis(10);
const ARCHIVE_MAX_TOTAL_SECONDS: u64 = 5 * 60 * 60;
const ARCHIVE_DELIVERY_BYTES_PER_SECOND: u64 = 128 * 1024;

pub(super) fn archive_total_timeout(entries: &[ArchiveEntry]) -> Duration {
    // Stored ZIP64 bytes include both member names, headers, data descriptors,
    // and the archive trailer. Allow conservative overhead even for empty files.
    let delivery_bytes = entries.iter().fold(256_u64, |total, entry| {
        total
            .saturating_add(entry.expected_size)
            .saturating_add(
                (entry.path.len() as u64)
                    .saturating_add(1)
                    .saturating_mul(2),
            )
            .saturating_add(256)
    });
    Duration::from_secs(
        delivery_bytes
            .div_ceil(ARCHIVE_DELIVERY_BYTES_PER_SECOND)
            .saturating_add(ARCHIVE_BACKPRESSURE_TIMEOUT.as_secs())
            .min(ARCHIVE_MAX_TOTAL_SECONDS),
    )
}

pub(super) fn archive_body<G>(
    entries: Vec<ArchiveEntry>,
    admission_permit: ArchiveProducerPermit,
    response_permit: G,
    entry_revalidator: Option<ArchiveEntryRevalidator>,
    total_timeout: Duration,
) -> Body
where
    G: Send + 'static,
{
    let delivery_deadline = Instant::now() + total_timeout;
    let (sender, receiver) = mpsc::channel::<Result<Bytes, io::Error>>(16);
    let (producer_done_tx, producer_done_rx) = oneshot::channel();
    // Closing delivery cancels the queue, but capacity belongs to the blocking
    // producer until it actually exits, including any in-flight disk/revalidation
    // work. A receiver timeout must never advertise a free live producer slot.
    let body = guard_blob_receiver_with_total_deadline(
        receiver,
        (),
        delivery_deadline.saturating_duration_since(Instant::now()),
        producer_done_rx,
    );
    let producer_errors = sender.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(error) = write_archive(
            ChannelWriter {
                sender,
                backpressure_timeout: ARCHIVE_BACKPRESSURE_TIMEOUT,
                delivery_deadline,
            },
            entries,
            entry_revalidator,
        ) {
            tracing::warn!(error = %error, "streaming ZIP production failed");
            let _ = producer_errors.try_send(Err(error));
        }
        drop(producer_errors);
        drop(response_permit);
        drop(admission_permit);
        let _ = producer_done_tx.send(());
    });
    body
}

pub(super) struct ChannelWriter {
    pub(super) sender: mpsc::Sender<Result<Bytes, io::Error>>,
    pub(super) backpressure_timeout: Duration,
    pub(super) delivery_deadline: Instant,
}

impl Write for ChannelWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let idle_deadline = Instant::now() + self.backpressure_timeout;
        let mut message = Ok(Bytes::copy_from_slice(buffer));
        loop {
            if Instant::now() >= self.delivery_deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "archive exceeded its total delivery deadline",
                ));
            }
            match self.sender.try_send(message) {
                Ok(()) => return Ok(buffer.len()),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "archive client disconnected",
                    ));
                }
                Err(mpsc::error::TrySendError::Full(returned)) => {
                    if Instant::now() >= idle_deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "archive client stopped draining the response",
                        ));
                    }
                    message = returned;
                    std::thread::sleep(ARCHIVE_BACKPRESSURE_RETRY);
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
