//! Content-addressed blob store: files are keyed by the hex SHA-256 of their
//! bytes and laid out two levels deep (`blobs/<first-2-hex>/<full-hash>`), which
//! deduplicates identical content across files, revisions, and workspaces.
//!
//! Writes are crash-safe (temp-write-then-atomic-rename, see [`put_blob`]) and
//! orphans (a blob whose DB row insert later failed, or that a crash stranded)
//! are reclaimed by the reference-counted GC sweep — [`scan_blobs_for_gc`]
//! enumerates candidates and the maintenance route removes the unreferenced
//! ones with [`remove_blob`]. Callers are `src/routes/*` (write/read) and
//! `storage.rs` (backup encode); the sweep is driven from
//! `routes/maintenance.rs`.

use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};

#[cfg(unix)]
use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};

#[cfg(windows)]
#[path = "blob/windows_lock.rs"]
mod windows_lock;

use sha2::{Digest, Sha256};

use crate::fs_private;

/// Monotonic counter that makes concurrent temp-file names unique within the
/// process (two tasks writing the *same* hash at the same nanosecond).
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const LIFECYCLE_LOCK_FILE: &str = ".blob-lifecycle.lock";

pub const MAX_GC_BATCH_SIZE: usize = 1_000;
/// Maximum number of on-disk entries a single GC request may examine while it
/// holds the exclusive publication lock. Stores whose deterministic page
/// cannot be proven within this ceiling require a durable blob inventory.
pub const MAX_GC_INSPECTED_ENTRIES: usize = 10_000;
const GC_OBJECT_BUDGET_ERROR: &str = "blob GC object_budget_exceeded";

/// Cross-process lifecycle guard for the content-addressed blob store.
///
/// Publishers take a shared guard before staging or adopting a blob and retain
/// it through the transaction that creates its database reference. Cleaners
/// take an exclusive guard before checking references and retain it through
/// unlink. This prevents a cleaner from deleting a same-hash blob while a
/// concurrent request has adopted it but has not committed its reference yet.
/// The guard is backed by a persistent, private file directly under the data
/// directory so separately started service processes coordinate even when a
/// test or maintenance action recreates the `blobs/` directory.
pub struct BlobLifecycleLock {
    file: fs::File,
}

impl BlobLifecycleLock {
    /// Acquire the shared publisher side of the lifecycle lock. Call this
    /// before any database transaction that will publish a blob reference.
    pub fn acquire_shared(root: &Path) -> io::Result<Self> {
        Self::acquire(root, LifecycleLockMode::Shared)
    }

    /// Acquire the exclusive cleaner side of the lifecycle lock. Call this
    /// before checking references and retain it through physical deletion.
    pub fn acquire_exclusive(root: &Path) -> io::Result<Self> {
        Self::acquire(root, LifecycleLockMode::Exclusive)
    }

    fn acquire(root: &Path, mode: LifecycleLockMode) -> io::Result<Self> {
        let path = root.join(LIFECYCLE_LOCK_FILE);
        let mut options = fs::OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        #[cfg(windows)]
        fs_private::configure_private_lock_options(
            &mut options,
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
        );
        let file = options.open(&path)?;
        #[cfg(windows)]
        fs_private::apply_private_file_handle(&file)?;
        #[cfg(not(windows))]
        fs_private::set_file_private(&path)?;
        lock_file(&file, mode)?;
        Ok(Self { file })
    }
}

impl Drop for BlobLifecycleLock {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
    }
}

#[derive(Clone, Copy)]
enum LifecycleLockMode {
    Shared,
    Exclusive,
}

#[cfg(unix)]
fn lock_file(file: &fs::File, mode: LifecycleLockMode) -> io::Result<()> {
    let operation = match mode {
        LifecycleLockMode::Shared => libc::LOCK_SH,
        LifecycleLockMode::Exclusive => libc::LOCK_EX,
    };
    // SAFETY: `file` remains open for the lifetime of the lock and its raw file
    // descriptor is valid for this process.
    if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn lock_file(file: &fs::File, mode: LifecycleLockMode) -> io::Result<()> {
    windows_lock::lock(file, matches!(mode, LifecycleLockMode::Exclusive))
}

#[cfg(not(any(unix, windows)))]
fn lock_file(_file: &fs::File, _mode: LifecycleLockMode) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "blob lifecycle locking requires an OS file-lock implementation",
    ))
}

#[cfg(unix)]
fn unlock_file(file: &fs::File) -> io::Result<()> {
    // SAFETY: `file` remains open for the duration of this call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn unlock_file(file: &fs::File) -> io::Result<()> {
    windows_lock::unlock(file)
}

#[cfg(not(any(unix, windows)))]
fn unlock_file(_file: &fs::File) -> io::Result<()> {
    Ok(())
}

/// Acquire a publisher lifecycle lock without blocking an async request worker.
pub async fn acquire_shared_lifecycle_lock(root: PathBuf) -> io::Result<BlobLifecycleLock> {
    tokio::task::spawn_blocking(move || BlobLifecycleLock::acquire_shared(&root))
        .await
        .map_err(|error| io::Error::other(format!("blob lifecycle lock task failed: {error}")))?
}

/// Acquire a cleaner lifecycle lock without blocking an async request worker.
pub async fn acquire_exclusive_lifecycle_lock(root: PathBuf) -> io::Result<BlobLifecycleLock> {
    tokio::task::spawn_blocking(move || BlobLifecycleLock::acquire_exclusive(&root))
        .await
        .map_err(|error| io::Error::other(format!("blob lifecycle lock task failed: {error}")))?
}

/// Store `content` and return its hex SHA-256 hash.
///
/// Crash-safety: the bytes are written to a unique `<hash>.<pid>.<n>.tmp` file
/// in the destination shard, `fsync`'d, then **atomically renamed** into
/// `<hash>`. A `rename(2)` within a directory is atomic on POSIX, so a reader
/// (or the GC sweep) never observes a partially written blob at `<hash>`: the
/// name either does not exist or points at complete, hash-matching content.
/// This closes the torn-write window the old direct-write path left open.
///
/// Content-addressed dedup: if `<hash>` already exists the bytes are identical,
/// so the temp file is discarded and only permissions are re-asserted.
/// Reference-publishing callers must retain a shared [`BlobLifecycleLock`]
/// from this call through their database commit.
pub fn put_blob(root: &Path, content: &[u8]) -> io::Result<String> {
    Ok(put_blob_with_outcome(root, content)?.hash)
}

/// Store an in-memory body and report whether this call created the durable
/// content-addressed object. Failure compensation must only remove objects
/// created by the failed request; a pre-existing or concurrently published
/// deduplicated blob may already be referenced by another writer.
pub fn put_blob_with_outcome(root: &Path, content: &[u8]) -> io::Result<BlobFilePublication> {
    let hash = hex::encode(Sha256::digest(content));
    let (blob_root, dir, path) = blob_path(root, &hash)?;
    fs_private::create_dir_all_private(&dir)?;
    fs_private::set_dir_private(&blob_root)?;

    if path.exists() {
        // Already stored (same bytes by definition of the hash). Nothing to do
        // but make sure permissions are locked down.
        fs_private::set_file_private(&path)?;
        return Ok(BlobFilePublication {
            hash,
            size: content.len() as u64,
            created: false,
        });
    }

    let tmp_path = temp_blob_path(&dir, &hash);
    let temporary = TemporaryBlobFile::new(tmp_path);
    fs_private::write_file_private(temporary.path(), content)?;
    let created = publish_temp_noclobber(temporary.path(), &path)?;
    if !created {
        fs_private::set_file_private(&path)?;
    }
    Ok(BlobFilePublication {
        hash,
        size: content.len() as u64,
        created,
    })
}

/// Copy an already-written file into the content-addressed store without
/// loading it into memory. The source remains intact so callers can retry a
/// later database failure; remove it only after metadata commits successfully.
/// Reference-publishing callers must retain a shared [`BlobLifecycleLock`]
/// from this call through their database commit.
pub fn put_blob_file(root: &Path, source: &Path) -> io::Result<(String, u64)> {
    let publication = put_blob_file_with_outcome(root, source)?;
    Ok((publication.hash, publication.size))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobFilePublication {
    pub hash: String,
    pub size: u64,
    /// True only when this call won the atomic rename and created the durable
    /// destination. Failure compensation must never remove a preexisting or
    /// concurrently published deduplicated blob.
    pub created: bool,
}

pub fn put_blob_file_with_outcome(root: &Path, source: &Path) -> io::Result<BlobFilePublication> {
    let mut file = fs::File::open(source)?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("blob size overflow"))?;
    }
    drop(file);

    let hash = hex::encode(hasher.finalize());
    put_blob_file_with_expected_outcome(root, source, &hash, size)
}

/// Copy a private staged file into the blob store after its ingress stream has
/// already counted and hashed it. The copied bytes are still re-hashed before
/// they receive their content-addressed name, so an interrupted or changed
/// staging file cannot publish under an unrelated digest.
pub fn put_blob_file_with_expected_outcome(
    root: &Path,
    source: &Path,
    expected_hash: &str,
    expected_size: u64,
) -> io::Result<BlobFilePublication> {
    let source_size = source.metadata()?.len();
    if source_size != expected_size {
        return Err(io::Error::other(
            "staged upload size changed before publication",
        ));
    }
    let hash = expected_hash.to_ascii_lowercase();
    let (blob_root, dir, destination) = blob_path(root, &hash)?;
    fs_private::create_dir_all_private(&dir)?;
    fs_private::set_dir_private(&blob_root)?;
    if destination.exists() {
        fs_private::set_file_private(&destination)?;
        return Ok(BlobFilePublication {
            hash,
            size: expected_size,
            created: false,
        });
    }

    let tmp_path = temp_blob_path(&dir, &hash);
    let temporary = TemporaryBlobFile::new(tmp_path);
    fs::copy(source, temporary.path())?;
    fs_private::set_file_private(temporary.path())?;
    let copied_hash = {
        let mut buffer = [0u8; 64 * 1024];
        let mut copied = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(temporary.path())?;
        let mut copied_hasher = Sha256::new();
        let mut copied_size = 0u64;
        loop {
            let read = copied.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            copied_hasher.update(&buffer[..read]);
            copied_size = copied_size
                .checked_add(read as u64)
                .ok_or_else(|| io::Error::other("blob size overflow"))?;
        }
        copied.sync_all()?;
        if copied_size != expected_size {
            return Err(io::Error::other("upload changed while being stored"));
        }
        hex::encode(copied_hasher.finalize())
    };
    if copied_hash != hash {
        return Err(io::Error::other("upload changed while being stored"));
    }

    let created = publish_temp_noclobber(temporary.path(), &destination)?;
    if !created {
        fs_private::set_file_private(&destination)?;
    }
    Ok(BlobFilePublication {
        hash,
        size: expected_size,
        created,
    })
}

/// Own a unique staging name until publication succeeds or any intermediate
/// read, hash, permission, sync, or publish step fails.
struct TemporaryBlobFile {
    path: PathBuf,
}

impl TemporaryBlobFile {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryBlobFile {
    fn drop(&mut self) {
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(path = %self.path.display(), %error, "failed to remove blob staging file")
            }
        }
    }
}

/// Atomically publish without replacing a concurrent winner. Hard-linking a
/// fully synced private staging file gives the destination an all-or-nothing
/// name while preserving correct `created` ownership for compensation.
fn publish_temp_noclobber(temporary: &Path, destination: &Path) -> io::Result<bool> {
    match fs::hard_link(temporary, destination) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(_error) if destination.exists() => Ok(false),
        Err(error) => Err(error),
    }
}

/// Return the validated on-disk path for streaming callers.
pub fn blob_file_path(root: &Path, hash: &str) -> io::Result<PathBuf> {
    let (_, _, path) = blob_path(root, hash)?;
    Ok(path)
}

/// Legacy whole-object reader retained only for compatibility tests. Production
/// adapters must use a bounded reader or [`blob_file_path`] plus the shared
/// disk-streaming response helper instead.
pub fn get_blob(root: &Path, hash: &str) -> io::Result<Vec<u8>> {
    let (_, _, path) = blob_path(root, hash)?;
    fs::read(path)
}

/// Read only a bounded prefix of a blob.
///
/// Callers use this for fixed-size format signatures.  It deliberately cannot
/// become a convenient whole-object read: full content must be sent through
/// the disk-streaming response helper instead.
pub fn get_blob_prefix(root: &Path, hash: &str, max_bytes: u64) -> io::Result<Vec<u8>> {
    let (_, _, path) = blob_path(root, hash)?;
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max_bytes).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Read at most `max_bytes` from a blob. `None` means the immutable object is
/// larger than the processing budget; no oversized allocation is attempted.
pub fn get_blob_limited(root: &Path, hash: &str, max_bytes: u64) -> io::Result<Option<Vec<u8>>> {
    let (_, _, path) = blob_path(root, hash)?;
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > max_bytes {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        Ok(None)
    } else {
        Ok(Some(bytes))
    }
}

/// Physically remove a content object. Callers must retain an exclusive
/// [`BlobLifecycleLock`] from the reference check through this call.
pub fn remove_blob(root: &Path, hash: &str) -> io::Result<bool> {
    let (_, _, path) = blob_path(root, hash)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Result of a GC scan of the blob directory.
#[derive(Debug, Default)]
pub struct BlobScan {
    /// `(hash, size_bytes)` for every stored blob old enough to be considered
    /// for removal. The caller reference-counts each hash against the DB and
    /// removes the truly-unreferenced ones with [`remove_blob`].
    pub candidates: Vec<(String, u64)>,
    /// Count of blobs skipped because they were modified within the grace
    /// window (protects in-flight uploads whose DB row has not committed yet).
    pub skipped_recent: u64,
    /// Count of stale `*.tmp` files (interrupted `put_blob` writes) removed.
    pub tmp_removed: u64,
    /// Number of directory entries examined in this request. Recent, temporary,
    /// malformed, and candidate entries all consume the same hard work budget.
    pub inspected_entries: u64,
    /// Exclusive canonical-hash cursor for the next deterministic batch.
    /// `None` means the scan reached the store's end.
    pub next_cursor: Option<String>,
    pub more_available: bool,
}

/// Return one deterministic page of stored blobs older than `min_age`. At most
/// `limit` candidates are materialized. Every directory entry examined,
/// including recent and malformed entries, consumes the fixed
/// [`MAX_GC_INSPECTED_ENTRIES`] work budget. If a complete deterministic page
/// cannot be proven within that ceiling, the scan fails without returning a
/// cursor or unlinking any blob or temporary file.
///
/// This does **not** consult the database — the reference check is the caller's
/// job (via `Storage::referenced_content_hashes`, which checks file content,
/// revisions, thumbnail/preview hashes, and folder covers in one set query).
/// References in every workspace and storage mode protect the shared blob.
///
/// `min_age` is a safety grace window. A `put_blob` writes the blob before its
/// DB row is inserted, so a freshly written blob may legitimately be
/// unreferenced for a brief moment; skipping recently modified blobs avoids
/// racing that window. Callers may pass `Duration::ZERO` when they know no
/// upload is in flight (e.g. tests, or a maintenance stop-the-world).
pub fn scan_blobs_for_gc(
    root: &Path,
    min_age: Duration,
    after: Option<&str>,
    limit: usize,
) -> io::Result<BlobScan> {
    if limit == 0 || limit > MAX_GC_BATCH_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("blob GC batch size must be between 1 and {MAX_GC_BATCH_SIZE}"),
        ));
    }
    let after = after
        .map(|hash| {
            if !is_canonical_blob_hash(hash) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "blob GC cursor must be a lowercase SHA-256 hash",
                ));
            }
            Ok(hash.to_string())
        })
        .transpose()?;
    let blob_root = root.join("blobs");
    let mut scan = BlobScan::default();
    let now = SystemTime::now();
    let start_shard = after
        .as_deref()
        .and_then(|hash| u8::from_str_radix(&hash[..2], 16).ok())
        .unwrap_or(0);
    let mut candidates = BTreeMap::<String, u64>::new();
    let mut stale_temporary_paths = Vec::new();

    for shard_index in start_shard..=u8::MAX {
        let shard_path = blob_root.join(format!("{shard_index:02x}"));
        let entries = match fs::read_dir(&shard_path) {
            Ok(entries) => entries,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        for entry in entries {
            scan.inspected_entries += 1;
            if scan.inspected_entries > MAX_GC_INSPECTED_ENTRIES as u64 {
                return Err(gc_object_budget_error());
            }
            let entry = entry?;
            let metadata = entry.metadata()?;
            if !metadata.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            let recent = is_within_grace(&metadata, now, min_age);

            if name.ends_with(".tmp") {
                if !recent {
                    stale_temporary_paths.push(entry.path());
                }
                continue;
            }
            if !is_canonical_blob_hash(&name)
                || after
                    .as_deref()
                    .is_some_and(|cursor| name.as_ref() <= cursor)
            {
                continue;
            }
            if recent {
                scan.skipped_recent += 1;
                continue;
            }
            candidates.insert(name.into_owned(), metadata.len());
            if candidates.len() > limit.saturating_add(1) {
                candidates.pop_last();
            }
        }
        if candidates.len() > limit {
            break;
        }
    }
    for path in stale_temporary_paths {
        if fs::remove_file(path).is_ok() {
            scan.tmp_removed += 1;
        }
    }
    scan.more_available = candidates.len() > limit;
    if scan.more_available {
        candidates.pop_last();
        scan.next_cursor = candidates.last_key_value().map(|(hash, _)| hash.clone());
    }
    scan.candidates = candidates.into_iter().collect();
    Ok(scan)
}

fn gc_object_budget_error() -> io::Error {
    io::Error::other(format!(
        "{GC_OBJECT_BUDGET_ERROR}: inspected-entry ceiling is {MAX_GC_INSPECTED_ENTRIES}; build a durable blob inventory before sweeping a larger store"
    ))
}

pub fn is_gc_object_budget_exceeded(error: &io::Error) -> bool {
    error.to_string().starts_with(GC_OBJECT_BUDGET_ERROR)
}

fn is_canonical_blob_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether `metadata`'s modified time is within `min_age` of `now` (i.e. too
/// recent to reap). A zero grace never protects; unknown or future timestamps
/// are treated as recent so the sweep fails safe and never removes a blob it
/// cannot age.
fn is_within_grace(metadata: &fs::Metadata, now: SystemTime, min_age: Duration) -> bool {
    if min_age.is_zero() {
        return false;
    }
    match metadata.modified() {
        Ok(modified) => now
            .duration_since(modified)
            .map(|age| age < min_age)
            .unwrap_or(true),
        Err(_) => true,
    }
}

/// Build a unique temp path in `dir` for staging a `put_blob` write. Includes
/// the hash (for debuggability), pid, and a per-process counter so concurrent
/// writers of the same hash never collide. Ends in `.tmp` so the GC scan and
/// blob lookups never mistake it for a finished blob.
fn temp_blob_path(dir: &Path, hash: &str) -> PathBuf {
    let pid = std::process::id();
    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    dir.join(format!("{hash}.{pid}.{seq}.{nanos}.tmp"))
}

fn blob_path(root: &Path, hash: &str) -> io::Result<(PathBuf, PathBuf, PathBuf)> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "blob hash must be 64 hex characters",
        ));
    }
    let hash = hash.to_ascii_lowercase();
    let blob_root = root.join("blobs");
    let dir = blob_root.join(&hash[0..2]);
    let path = dir.join(&hash);
    Ok((blob_root, dir, path))
}

#[cfg(all(test, windows))]
#[path = "blob/windows_lock_tests.rs"]
mod windows_lock_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_file_without_buffering_and_enforces_bounded_reads() {
        let temp = tempfile::tempdir().unwrap();
        let upload_dir = temp.path().join("uploads");
        fs::create_dir_all(&upload_dir).unwrap();
        let source = upload_dir.join("payload.part");
        let payload = vec![0x5a; 128 * 1024];
        fs::write(&source, &payload).unwrap();

        let first = put_blob_file_with_outcome(temp.path(), &source).unwrap();
        let hash = first.hash;
        let size = first.size;
        assert!(first.created);
        assert_eq!(size, payload.len() as u64);
        assert!(source.exists(), "source remains available until DB commit");
        assert_eq!(
            get_blob_limited(temp.path(), &hash, 256 * 1024).unwrap(),
            Some(payload.clone())
        );
        assert!(get_blob_limited(temp.path(), &hash, 1024)
            .unwrap()
            .is_none());

        let duplicate_source = upload_dir.join("duplicate.part");
        fs::write(&duplicate_source, &payload).unwrap();
        let duplicate = put_blob_file_with_outcome(temp.path(), &duplicate_source).unwrap();
        assert_eq!(duplicate.hash, hash);
        assert_eq!(duplicate.size, size);
        assert!(!duplicate.created);
        assert!(duplicate_source.exists());
    }

    #[test]
    fn gc_scan_cursor_resumes_without_duplicates_and_bounds_materialization() {
        let root = tempfile::tempdir().unwrap();
        let mut expected = (0..7)
            .map(|index| put_blob(root.path(), format!("orphan-{index}").as_bytes()).unwrap())
            .collect::<Vec<_>>();
        expected.sort();

        let mut actual = Vec::new();
        let mut cursor = None;
        loop {
            let page =
                scan_blobs_for_gc(root.path(), Duration::ZERO, cursor.as_deref(), 2).unwrap();
            assert!(page.candidates.len() <= 2);
            actual.extend(page.candidates.into_iter().map(|(hash, _)| hash));
            if !page.more_available {
                assert!(page.next_cursor.is_none());
                break;
            }
            cursor = page.next_cursor;
            assert!(cursor.is_some());
        }
        actual.sort();
        assert_eq!(actual, expected);
    }

    #[test]
    fn gc_scan_rejects_unbounded_or_noncanonical_pages() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            scan_blobs_for_gc(root.path(), Duration::ZERO, None, 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            scan_blobs_for_gc(root.path(), Duration::ZERO, Some(&"A".repeat(64)), 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn many_recent_entries_fail_closed_without_unlinking_or_advancing() {
        let root = tempfile::tempdir().unwrap();
        let shard = root.path().join("blobs/00");
        fs::create_dir_all(&shard).unwrap();
        let total = MAX_GC_INSPECTED_ENTRIES + 17;
        for index in 0..total {
            fs::write(shard.join(format!("{index:064x}")), []).unwrap();
        }
        let stale_temporary = shard.join(format!("{}.1.1.1.tmp", "f".repeat(64)));
        fs::write(&stale_temporary, []).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&stale_temporary)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))
            .unwrap();

        let error = scan_blobs_for_gc(root.path(), Duration::from_secs(3600), None, 2)
            .expect_err("the inspected-entry ceiling must fail before a cursor is returned");
        assert!(is_gc_object_budget_exceeded(&error), "{error}");
        assert!(stale_temporary.exists());
        assert_eq!(fs::read_dir(&shard).unwrap().count(), total + 1);
    }
}
