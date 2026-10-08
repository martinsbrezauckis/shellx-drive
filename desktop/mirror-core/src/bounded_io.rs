use std::{
    future::Future,
    io::{Read, Write},
    sync::{Arc, Mutex},
};

use sha2::{Digest, Sha256};

use crate::{hex_digest, DesktopError, LocalScanLimits, Result};

pub(crate) const BUFFER_BYTES: usize = 128 * 1024;

/// Preserve the established room for admission, terminal and move rechecks,
/// but share it across every configured root in one cycle.
pub fn sync_cycle_local_read_limit() -> u64 {
    LocalScanLimits::default()
        .max_total_file_bytes
        .saturating_mul(6)
}

tokio::task_local! {
    static CYCLE_READ_BUDGET: Arc<Mutex<ReadBudget>>;
}

/// Cover all local hashing and upload snapshot reads in one async sync cycle,
/// including terminal rechecks reached through platform-specific helpers.
pub async fn with_cycle_read_budget<F: Future>(max_bytes: u64, future: F) -> F::Output {
    CYCLE_READ_BUDGET
        .scope(
            Arc::new(Mutex::new(ReadBudget::new_cycle(max_bytes))),
            future,
        )
        .await
}

fn charge_cycle_read(bytes: u64) -> Result<()> {
    CYCLE_READ_BUDGET
        .try_with(|budget| {
            budget
                .lock()
                .map_err(|_| {
                    DesktopError::InvalidState("sync cycle read budget lock failed".to_string())
                })?
                .charge(bytes)
        })
        .unwrap_or(Ok(()))
}

#[derive(Debug)]
pub struct ReadBudget {
    remaining_bytes: u64,
    cycle: bool,
}

impl ReadBudget {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            remaining_bytes: max_bytes,
            cycle: false,
        }
    }

    pub fn new_cycle(max_bytes: u64) -> Self {
        Self {
            remaining_bytes: max_bytes,
            cycle: true,
        }
    }

    pub fn charge(&mut self, bytes: u64) -> Result<()> {
        self.remaining_bytes = self.remaining_bytes.checked_sub(bytes).ok_or_else(|| {
            let message = "local reads exceeded their byte budget".to_string();
            if self.cycle {
                DesktopError::SyncCycleBudgetExceeded(message)
            } else {
                DesktopError::InvalidState(message)
            }
        })?;
        Ok(())
    }
}

pub fn hash_reader_bounded(mut reader: impl Read, max_bytes: u64) -> Result<(String, u64)> {
    hash_and_copy_reader_bounded(
        &mut reader,
        Option::<&mut std::io::Sink>::None,
        max_bytes,
        &mut || Ok(()),
    )
}

pub fn hash_reader_bounded_with_cancellation(
    mut reader: impl Read,
    max_bytes: u64,
    mut check: impl FnMut() -> Result<()>,
) -> Result<(String, u64)> {
    hash_and_copy_reader_bounded(
        &mut reader,
        Option::<&mut std::io::Sink>::None,
        max_bytes,
        &mut check,
    )
}

pub fn copy_and_hash_reader_bounded(
    mut reader: impl Read,
    mut destination: impl Write,
    max_bytes: u64,
) -> Result<(String, u64)> {
    hash_and_copy_reader_bounded(&mut reader, Some(&mut destination), max_bytes, &mut || {
        Ok(())
    })
}

fn hash_and_copy_reader_bounded<R: Read, W: Write>(
    reader: &mut R,
    mut destination: Option<&mut W>,
    max_bytes: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        check()?;
        let remaining_plus_boundary = max_bytes
            .saturating_sub(total)
            .saturating_add(1)
            .min(buffer.len() as u64) as usize;
        let read = reader.read(&mut buffer[..remaining_plus_boundary])?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            DesktopError::InvalidState("local read byte count overflowed".to_string())
        })?;
        if total > max_bytes {
            return Err(DesktopError::InvalidState(format!(
                "local file grew beyond the {max_bytes}-byte scan limit"
            )));
        }
        charge_cycle_read(read as u64)?;
        if let Some(destination) = destination.as_deref_mut() {
            destination.write_all(&buffer[..read])?;
        }
        hasher.update(&buffer[..read]);
    }
    Ok((hex_digest(hasher.finalize().as_slice()), total))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Cursor;

    #[tokio::test]
    async fn cycle_counts_reads_across_independent_hash_calls() {
        with_cycle_read_budget(5, async {
            assert!(hash_reader_bounded(Cursor::new([1_u8; 3]), 3).is_ok());
            assert!(hash_reader_bounded(Cursor::new([2_u8; 2]), 2).is_ok());
            assert!(matches!(
                hash_reader_bounded(Cursor::new([3_u8; 1]), 1),
                Err(DesktopError::SyncCycleBudgetExceeded(_))
            ));
        })
        .await;
    }

    use super::*;

    #[test]
    fn bounded_copy_hashes_exact_bytes_and_rejects_the_boundary_byte() {
        let mut copied = Vec::new();
        let (hash, bytes) =
            copy_and_hash_reader_bounded(Cursor::new(b"safe"), &mut copied, 4).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(copied, b"safe");
        assert_eq!(
            hash,
            hash_reader_bounded(Cursor::new(b"safe"), 4).unwrap().0
        );

        let mut oversized_copy = Vec::new();
        assert!(
            copy_and_hash_reader_bounded(Cursor::new(b"unsafe"), &mut oversized_copy, 4,).is_err()
        );
        assert!(oversized_copy.len() <= 4);
    }

    #[test]
    fn read_budget_is_aggregate_and_fails_closed() {
        let mut budget = ReadBudget::new(4);
        budget.charge(1).unwrap();
        budget.charge(3).unwrap();
        assert!(budget.charge(1).is_err());
    }

    #[test]
    fn hashing_observes_cancellation_between_bounded_chunks() {
        let checks = Cell::new(0_u8);
        let payload = vec![b'x'; BUFFER_BYTES * 3];
        let result = hash_reader_bounded_with_cancellation(
            Cursor::new(payload),
            (BUFFER_BYTES * 3) as u64,
            || {
                let next = checks.get() + 1;
                checks.set(next);
                if next >= 2 {
                    return Err(DesktopError::SyncCancelledForDisconnect);
                }
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(DesktopError::SyncCancelledForDisconnect)
        ));
        assert_eq!(checks.get(), 2);
    }
}
