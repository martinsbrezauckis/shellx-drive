use std::{
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{bail, Context};

use crate::sync_client_fs::SafeCacheRoot;

use super::RESUMABLE_CHUNK_SIZE;

const DEFAULT_SYNC_PASS_MAX_WORKSPACES: usize = 64;
const DEFAULT_SYNC_PASS_MAX_MANIFEST_ITEMS: usize = 100_000;
const DEFAULT_SYNC_PASS_MAX_TRANSFERS: usize = 10_000;
const DEFAULT_SYNC_PASS_MAX_TRANSFER_BYTES: u64 = 20 * 1024 * 1024 * 1024;
const DEFAULT_SYNC_PASS_MAX_REQUESTS: usize = 50_000;
const DEFAULT_SYNC_PASS_MAX_ELAPSED: Duration = Duration::from_secs(2 * 60 * 60);
const DEFAULT_SYNC_MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RETAINED_RECOVERY_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Aggregate admission policy for one `sync_once` invocation. Defaults are
/// deliberately conservative; operators embedding the client can opt into a
/// larger explicit envelope with `SyncClient::with_pass_limits`.
#[derive(Clone, Copy, Debug)]
pub struct SyncPassLimits {
    pub max_workspaces: usize,
    pub max_manifest_items: usize,
    pub max_transfers: usize,
    pub max_transfer_bytes: u64,
    pub max_requests: usize,
    pub max_elapsed: Duration,
    pub min_free_bytes: u64,
}

impl Default for SyncPassLimits {
    fn default() -> Self {
        Self {
            max_workspaces: DEFAULT_SYNC_PASS_MAX_WORKSPACES,
            max_manifest_items: DEFAULT_SYNC_PASS_MAX_MANIFEST_ITEMS,
            max_transfers: DEFAULT_SYNC_PASS_MAX_TRANSFERS,
            max_transfer_bytes: DEFAULT_SYNC_PASS_MAX_TRANSFER_BYTES,
            max_requests: DEFAULT_SYNC_PASS_MAX_REQUESTS,
            max_elapsed: DEFAULT_SYNC_PASS_MAX_ELAPSED,
            min_free_bytes: DEFAULT_SYNC_MIN_FREE_BYTES,
        }
    }
}

pub(super) struct SyncPassBudget {
    limits: SyncPassLimits,
    started_at: Instant,
    manifest_items: usize,
    transfers: usize,
    transfer_bytes: u64,
    requests: usize,
    retained_recovery_bytes: Option<u64>,
}

impl SyncPassBudget {
    pub(super) fn new(limits: SyncPassLimits) -> Self {
        Self {
            limits,
            started_at: Instant::now(),
            manifest_items: 0,
            transfers: 0,
            transfer_bytes: 0,
            requests: 0,
            retained_recovery_bytes: None,
        }
    }

    pub(super) fn check_elapsed(&self) -> anyhow::Result<()> {
        if self.started_at.elapsed() > self.limits.max_elapsed {
            bail!(
                "sync pass exceeded its {:?} elapsed-time budget",
                self.limits.max_elapsed
            );
        }
        Ok(())
    }

    pub(super) fn admit_workspaces(&mut self, count: usize) -> anyhow::Result<()> {
        self.check_elapsed()?;
        if count > self.limits.max_workspaces {
            bail!(
                "sync pass selected {count} workspaces; limit is {}",
                self.limits.max_workspaces
            );
        }
        Ok(())
    }

    pub(super) fn add_manifest_items(&mut self, count: usize) -> anyhow::Result<()> {
        self.check_elapsed()?;
        self.manifest_items = self
            .manifest_items
            .checked_add(count)
            .context("sync pass manifest item count overflowed")?;
        if self.manifest_items > self.limits.max_manifest_items {
            bail!(
                "sync pass manifest total exceeds its {}-item limit",
                self.limits.max_manifest_items
            );
        }
        Ok(())
    }

    pub(super) fn add_requests(&mut self, count: usize) -> anyhow::Result<()> {
        self.check_elapsed()?;
        self.requests = self
            .requests
            .checked_add(count)
            .context("sync pass request count overflowed")?;
        if self.requests > self.limits.max_requests {
            bail!(
                "sync pass request estimate exceeds its {}-request limit",
                self.limits.max_requests
            );
        }
        Ok(())
    }

    pub(super) fn reserve_download(&mut self, cache_dir: &Path, bytes: u64) -> anyhow::Result<()> {
        self.reserve_transfer(bytes, 1)?;
        ensure_sync_free_space(cache_dir, bytes, self.limits.min_free_bytes)
    }

    pub(super) fn reserve_upload(&mut self, bytes: u64) -> anyhow::Result<()> {
        let chunk_requests = bytes
            .saturating_add(RESUMABLE_CHUNK_SIZE as u64 - 1)
            .saturating_div(RESUMABLE_CHUNK_SIZE as u64)
            .max(1);
        let requests = usize::try_from(chunk_requests.saturating_add(1))
            .context("sync upload request estimate overflowed")?;
        self.reserve_transfer(bytes, requests)
    }

    pub(super) fn reserve_recovery(
        &mut self,
        cache_root: &SafeCacheRoot,
        bytes: u64,
    ) -> anyhow::Result<()> {
        let retained = match self.retained_recovery_bytes {
            Some(retained) => retained,
            None => cache_root.retained_recovery_bytes()?,
        };
        let next = retained
            .checked_add(bytes)
            .context("sync recovery byte count overflowed")?;
        if next > MAX_RETAINED_RECOVERY_BYTES {
            bail!(
                "retained sync recovery bodies would exceed the {}-byte limit; review and move .remote-conflict files out of the cache",
                MAX_RETAINED_RECOVERY_BYTES
            );
        }
        self.retained_recovery_bytes = Some(next);
        Ok(())
    }

    /// Reconcile a pre-download estimate with the body actually displaced at
    /// publication time. The local leaf may change while the GET is in flight.
    pub(super) fn adjust_recovery_reservation(
        &mut self,
        estimated_bytes: u64,
        actual_bytes: u64,
    ) -> anyhow::Result<()> {
        let reserved = self
            .retained_recovery_bytes
            .context("sync recovery reservation was not initialized")?;
        let next = reserved
            .checked_sub(estimated_bytes)
            .and_then(|bytes| bytes.checked_add(actual_bytes))
            .context("sync recovery reservation count overflowed")?;
        if next > MAX_RETAINED_RECOVERY_BYTES {
            bail!(
                "retained sync recovery bodies would exceed the {}-byte limit; review and move .remote-conflict files out of the cache",
                MAX_RETAINED_RECOVERY_BYTES
            );
        }
        self.retained_recovery_bytes = Some(next);
        Ok(())
    }

    fn reserve_transfer(&mut self, bytes: u64, requests: usize) -> anyhow::Result<()> {
        self.check_elapsed()?;
        self.transfers = self
            .transfers
            .checked_add(1)
            .context("sync pass transfer count overflowed")?;
        self.transfer_bytes = self
            .transfer_bytes
            .checked_add(bytes)
            .context("sync pass transfer byte count overflowed")?;
        if self.transfers > self.limits.max_transfers {
            bail!(
                "sync pass exceeds its {}-transfer limit",
                self.limits.max_transfers
            );
        }
        if self.transfer_bytes > self.limits.max_transfer_bytes {
            bail!(
                "sync pass exceeds its {}-byte aggregate transfer limit",
                self.limits.max_transfer_bytes
            );
        }
        self.add_requests(requests)
    }
}

fn ensure_sync_free_space(
    path: &Path,
    payload_bytes: u64,
    reserve_bytes: u64,
) -> anyhow::Result<()> {
    let required = payload_bytes
        .checked_add(reserve_bytes)
        .context("sync download free-space requirement overflowed")?;
    if let Some(available) = sync_available_space_bytes(path)? {
        if available < required {
            bail!(
                "sync download requires {required} free bytes including reserve; only {available} are available"
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn sync_available_space_bytes(path: &Path) -> std::io::Result<Option<u64>> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stats` points to writable storage.
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful statvfs call initializes the full structure.
    let stats = unsafe { stats.assume_init() };
    #[cfg(target_vendor = "apple")]
    let available_blocks = u64::from(stats.f_bavail);
    #[cfg(not(target_vendor = "apple"))]
    let available_blocks = stats.f_bavail;
    Ok(Some(available_blocks.saturating_mul(stats.f_frsize)))
}

#[cfg(windows)]
fn sync_available_space_bytes(path: &Path) -> std::io::Result<Option<u64>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut available = 0u64;
    let result = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Some(available))
}

#[cfg(not(any(unix, windows)))]
fn sync_available_space_bytes(_path: &Path) -> std::io::Result<Option<u64>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crate::sync_client_fs::{ensure_cache_directory, ensure_cache_root, SafeDownloadTarget};

    use super::*;

    fn tiny_limits() -> SyncPassLimits {
        SyncPassLimits {
            max_workspaces: 1,
            max_manifest_items: 2,
            max_transfers: 1,
            max_transfer_bytes: 4,
            max_requests: 2,
            max_elapsed: Duration::from_secs(60),
            min_free_bytes: 0,
        }
    }

    #[test]
    fn aggregate_sync_budget_rejects_each_multiplication_axis() {
        let mut budget = SyncPassBudget::new(tiny_limits());
        assert!(budget.admit_workspaces(2).is_err());

        let mut budget = SyncPassBudget::new(tiny_limits());
        budget.add_manifest_items(2).unwrap();
        assert!(budget.add_manifest_items(1).is_err());

        let mut budget = SyncPassBudget::new(tiny_limits());
        budget.reserve_upload(4).unwrap();
        assert!(budget.reserve_upload(1).is_err());

        let mut budget = SyncPassBudget::new(tiny_limits());
        assert!(budget.add_requests(3).is_err());
    }

    #[test]
    fn download_reserve_is_checked_before_staging() {
        let data = tempfile::tempdir().unwrap();
        let mut limits = tiny_limits();
        limits.min_free_bytes = u64::MAX;
        limits.max_transfer_bytes = u64::MAX;
        let mut budget = SyncPassBudget::new(limits);
        assert!(budget.reserve_download(data.path(), 1).is_err());
        assert!(data.path().read_dir().unwrap().next().is_none());
    }

    #[test]
    fn recovery_reservation_counts_persisted_and_current_pass_bodies() {
        #[cfg(unix)]
        let fixture = crate::sync_client_fs::unix_test_support::private_tempdir();
        #[cfg(not(unix))]
        let fixture = tempfile::tempdir().unwrap();
        let cache = ensure_cache_root(&fixture.path().join("cache")).unwrap();
        let content = ensure_cache_directory(&cache, Path::new("workspaces/one/content")).unwrap();
        let mut target =
            SafeDownloadTarget::begin(&cache, &content.join("a.local-1.remote-conflict")).unwrap();
        target.file_mut().write_all(b"old").unwrap();
        target.commit_new().unwrap();

        let mut budget = SyncPassBudget::new(tiny_limits());
        budget
            .reserve_recovery(&cache, MAX_RETAINED_RECOVERY_BYTES - 3)
            .unwrap();
        assert!(budget
            .reserve_recovery(&cache, 1)
            .unwrap_err()
            .to_string()
            .contains("retained sync recovery bodies"));

        let mut next_pass = SyncPassBudget::new(tiny_limits());
        assert!(next_pass
            .reserve_recovery(&cache, MAX_RETAINED_RECOVERY_BYTES - 2)
            .is_err());
    }

    #[test]
    fn recovery_reservation_uses_displaced_size_after_a_local_change() {
        #[cfg(unix)]
        let fixture = crate::sync_client_fs::unix_test_support::private_tempdir();
        #[cfg(not(unix))]
        let fixture = tempfile::tempdir().unwrap();
        let cache = ensure_cache_root(&fixture.path().join("cache")).unwrap();
        let mut budget = SyncPassBudget::new(tiny_limits());
        budget
            .reserve_recovery(&cache, MAX_RETAINED_RECOVERY_BYTES - 5)
            .unwrap();
        budget.reserve_recovery(&cache, 1).unwrap();
        assert!(budget.adjust_recovery_reservation(1, 10).is_err());
        budget.adjust_recovery_reservation(1, 3).unwrap();
        assert_eq!(
            budget.retained_recovery_bytes,
            Some(MAX_RETAINED_RECOVERY_BYTES - 2)
        );
    }
}
