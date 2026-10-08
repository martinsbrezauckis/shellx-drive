use std::{
    io,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

const DEFAULT_EVICT_INTERVAL: u64 = 8 * 1024 * 1024;

/// An async file reader that prevents large sequential downloads from leaving
/// the entire file charged to the service cgroup as inactive page cache.
pub(crate) struct CacheDroppingFile {
    file: tokio::fs::File,
    position: u64,
    evicted_through: u64,
    evict_interval: u64,
}

impl CacheDroppingFile {
    /// Wrap a caller-owned descriptor so a response can stream the exact file
    /// it already verified, while retaining sequential/cache-drop advice.
    pub(crate) fn from_std(file: std::fs::File) -> Self {
        let file = tokio::fs::File::from_std(file);
        advise_sequential(&file);
        Self {
            file,
            position: 0,
            evicted_through: 0,
            evict_interval: DEFAULT_EVICT_INTERVAL,
        }
    }

    fn evict_completed_ranges(&mut self) {
        let through = self.position / self.evict_interval * self.evict_interval;
        if through <= self.evicted_through {
            return;
        }
        advise_dontneed(
            &self.file,
            self.evicted_through,
            through - self.evicted_through,
        );
        self.evicted_through = through;
    }

    #[cfg(test)]
    fn with_interval(mut self, interval: u64) -> Self {
        self.evict_interval = interval.max(1);
        self
    }
}

impl AsyncRead for CacheDroppingFile {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut self.file).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                self.position = self
                    .position
                    .saturating_add((buffer.filled().len() - before) as u64);
                self.evict_completed_ranges();
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl Drop for CacheDroppingFile {
    fn drop(&mut self) {
        // Length zero means through EOF. This also releases pages pulled in by
        // kernel readahead but not consumed when a client cancels a download.
        advise_dontneed(&self.file, 0, 0);
    }
}

/// Best-effort cleanup for synchronous archive jobs. Keeping a descriptor open
/// makes the cleanup run on every return path, including validation failures.
pub(crate) struct FileCacheDropGuard(Option<std::fs::File>);

impl FileCacheDropGuard {
    pub(crate) fn for_path(path: &Path) -> Self {
        Self(std::fs::File::open(path).ok())
    }
}

impl Drop for FileCacheDropGuard {
    fn drop(&mut self) {
        if let Some(file) = &self.0 {
            advise_dontneed(file, 0, 0);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn advise_sequential(file: &tokio::fs::File) {
    use std::os::fd::AsRawFd;

    advise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn advise_sequential(_file: &tokio::fs::File) {}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn advise_dontneed<T: std::os::fd::AsRawFd>(file: &T, offset: u64, length: u64) {
    advise(file.as_raw_fd(), offset, length, libc::POSIX_FADV_DONTNEED);
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn advise_dontneed<T>(_file: &T, _offset: u64, _length: u64) {}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn advise(fd: std::os::fd::RawFd, offset: u64, length: u64, advice: libc::c_int) {
    let (Ok(offset), Ok(length)) = (libc::off_t::try_from(offset), libc::off_t::try_from(length))
    else {
        return;
    };
    // SAFETY: `fd` belongs to a live file and the converted offsets are valid.
    // posix_fadvise is advisory; failures intentionally do not affect I/O.
    unsafe {
        libc::posix_fadvise(fd, offset, length, advice);
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::CacheDroppingFile;

    #[tokio::test]
    async fn streams_complete_file_while_advancing_eviction_window() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large.bin");
        let expected = vec![0x5a; 20 * 1024];
        std::fs::write(&path, &expected).unwrap();

        let mut reader = CacheDroppingFile::from_std(std::fs::File::open(&path).unwrap())
            .with_interval(4 * 1024);
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).await.unwrap();

        assert_eq!(actual, expected);
        assert_eq!(reader.position, expected.len() as u64);
        assert_eq!(reader.evicted_through, expected.len() as u64);
    }
}
