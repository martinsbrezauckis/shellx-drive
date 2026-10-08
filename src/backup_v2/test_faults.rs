use std::{cell::Cell, io};

thread_local! {
    static ARCHIVE_WRITE_REMAINING: Cell<Option<u64>> = const { Cell::new(None) };
    static AVAILABLE_SPACE_BYTES: Cell<Option<u64>> = const { Cell::new(None) };
}

pub(super) struct ArchiveWriteFailureScope {
    previous: Option<u64>,
}

impl Drop for ArchiveWriteFailureScope {
    fn drop(&mut self) {
        ARCHIVE_WRITE_REMAINING.with(|remaining| remaining.set(self.previous));
    }
}

pub(super) fn fail_archive_writes_after(bytes: u64) -> ArchiveWriteFailureScope {
    let previous = ARCHIVE_WRITE_REMAINING.with(|remaining| {
        let previous = remaining.get();
        remaining.set(Some(bytes));
        previous
    });
    ArchiveWriteFailureScope { previous }
}

pub(super) struct AvailableSpaceScope {
    previous: Option<u64>,
}

impl Drop for AvailableSpaceScope {
    fn drop(&mut self) {
        AVAILABLE_SPACE_BYTES.with(|available| available.set(self.previous));
    }
}

pub(super) fn override_available_space(bytes: u64) -> AvailableSpaceScope {
    let previous = AVAILABLE_SPACE_BYTES.with(|available| {
        let previous = available.get();
        available.set(Some(bytes));
        previous
    });
    AvailableSpaceScope { previous }
}

pub(super) fn available_space_override() -> Option<u64> {
    AVAILABLE_SPACE_BYTES.with(Cell::get)
}

pub(super) fn next_archive_write_len(requested: usize) -> io::Result<usize> {
    ARCHIVE_WRITE_REMAINING.with(|remaining| match remaining.get() {
        Some(0) => Err(io::Error::from_raw_os_error(libc::ENOSPC)),
        Some(limit) => Ok(usize::try_from(limit.min(requested as u64)).unwrap_or(requested)),
        None => Ok(requested),
    })
}

pub(super) fn record_archive_write(bytes: usize) {
    ARCHIVE_WRITE_REMAINING.with(|remaining| {
        if let Some(limit) = remaining.get() {
            remaining.set(Some(limit - bytes as u64));
        }
    });
}
