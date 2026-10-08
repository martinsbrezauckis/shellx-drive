//! Failure-safe publication of content-addressed bodies from product routes.
//!
//! A blob is durable before the SQLite row which accounts for it can commit.
//! This guard retains the shared publisher lock through that commit and, on
//! failure, upgrades to the exclusive cleaner side before reference-checking
//! and removing only objects this request actually created.

use std::{
    collections::BTreeSet,
    panic::{catch_unwind, AssertUnwindSafe},
    path::PathBuf,
};

use crate::{
    blob::{self, BlobFilePublication, BlobLifecycleLock},
    error::ApiResult,
    server::AppState,
    storage::Storage,
};

pub(crate) struct PendingBlobPublications {
    data_dir: PathBuf,
    storage: Storage,
    shared_lock: Option<BlobLifecycleLock>,
    publications: Vec<BlobFilePublication>,
    runtime: tokio::runtime::Handle,
}

impl PendingBlobPublications {
    pub(crate) async fn acquire(state: &AppState) -> ApiResult<Self> {
        let data_dir = state.data_dir();
        let shared_lock = blob::acquire_shared_lifecycle_lock(data_dir.clone()).await?;
        Ok(Self::with_lock(state, data_dir, shared_lock))
    }

    /// Acquire inside an already-admitted blocking worker. This lets callers
    /// place fail-fast compute admission before the filesystem lock while still
    /// retaining publication compensation across request cancellation.
    pub(crate) fn acquire_blocking(state: &AppState) -> ApiResult<Self> {
        let data_dir = state.data_dir();
        let shared_lock = BlobLifecycleLock::acquire_shared(&data_dir)?;
        Ok(Self::with_lock(state, data_dir, shared_lock))
    }

    fn with_lock(state: &AppState, data_dir: PathBuf, shared_lock: BlobLifecycleLock) -> Self {
        Self {
            data_dir,
            storage: state.storage.clone(),
            shared_lock: Some(shared_lock),
            publications: Vec::new(),
            runtime: tokio::runtime::Handle::current(),
        }
    }

    pub(crate) fn put_bytes(&mut self, content: &[u8]) -> ApiResult<BlobFilePublication> {
        let publication = blob::put_blob_with_outcome(&self.data_dir, content)?;
        self.publications.push(publication.clone());
        Ok(publication)
    }

    pub(crate) fn put_file(&mut self, source: &std::path::Path) -> ApiResult<BlobFilePublication> {
        let publication = blob::put_blob_file_with_outcome(&self.data_dir, source)?;
        self.publications.push(publication.clone());
        Ok(publication)
    }

    /// Publish a file whose request stream has already produced the declared
    /// digest and byte count. `blob` verifies its private copy before naming
    /// it, so this avoids a second full read of the staging input without
    /// weakening content-addressed integrity.
    pub(crate) fn put_file_with_expected_digest(
        &mut self,
        source: &std::path::Path,
        hash: &str,
        size: u64,
    ) -> ApiResult<BlobFilePublication> {
        let publication =
            blob::put_blob_file_with_expected_outcome(&self.data_dir, source, hash, size)?;
        self.publications.push(publication.clone());
        Ok(publication)
    }

    pub(crate) async fn finish<T>(mut self, result: ApiResult<T>) -> ApiResult<T> {
        if result.is_ok() || !self.publications.iter().any(|item| item.created) {
            self.publications.clear();
            drop(self.shared_lock.take());
            return result;
        }

        if let Some(cleanup) = self.schedule_cleanup() {
            // The independently owned task survives cancellation of this
            // request while it waits for exclusive lifecycle ownership.
            if let Err(error) = cleanup.await {
                tracing::error!(%error, "blob compensation task failed");
            }
        }
        result
    }

    fn schedule_cleanup(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        if !self.publications.iter().any(|item| item.created) {
            self.publications.clear();
            drop(self.shared_lock.take());
            return None;
        }
        let data_dir = self.data_dir.clone();
        let storage = self.storage.clone();
        let publications = std::mem::take(&mut self.publications);
        let shared_lock = self.shared_lock.take();
        Some(self.runtime.spawn(async move {
            drop(shared_lock);
            let cleanup = async {
                let _exclusive_lock =
                    blob::acquire_exclusive_lifecycle_lock(data_dir.clone()).await?;
                remove_created_unreferenced(&storage, &data_dir, &publications)
            }
            .await;
            if let Err(error) = cleanup {
                tracing::error!(%error, "failed to compensate rejected blob publication");
            }
        }))
    }
}

impl Drop for PendingBlobPublications {
    fn drop(&mut self) {
        // Covers request cancellation, abandoned spawn_blocking results, and
        // unwinds before `finish` is reached.
        let _ = self.schedule_cleanup();
    }
}

/// Run a synchronous publication-plus-database operation while retaining the
/// lifecycle lock, then compensate any rejected durable bodies asynchronously.
pub(crate) async fn run<T, F>(state: &AppState, operation: F) -> ApiResult<T>
where
    F: FnOnce(&mut PendingBlobPublications) -> ApiResult<T>,
{
    let mut pending = PendingBlobPublications::acquire(state).await?;
    let result = catch_unwind(AssertUnwindSafe(|| operation(&mut pending))).unwrap_or_else(|_| {
        Err(crate::error::ApiError::Maintenance(
            "blob publication operation panicked".to_string(),
        ))
    });
    pending.finish(result).await
}

fn remove_created_unreferenced(
    storage: &Storage,
    data_dir: &std::path::Path,
    publications: &[BlobFilePublication],
) -> ApiResult<()> {
    let hashes = publications
        .iter()
        .filter(|publication| publication.created)
        .map(|publication| publication.hash.as_str())
        .collect::<BTreeSet<_>>();
    for hash in hashes {
        if !storage.content_hash_is_referenced(hash)? {
            blob::remove_blob(data_dir, hash)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CreateFileRequest, FileKind};

    #[test]
    fn cleanup_removes_only_new_unreferenced_objects() {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();

        let shared = BlobLifecycleLock::acquire_shared(temp.path()).unwrap();
        let orphan = blob::put_blob_with_outcome(temp.path(), b"new orphan").unwrap();
        let duplicate = blob::put_blob_with_outcome(temp.path(), b"new orphan").unwrap();
        let referenced = blob::put_blob_with_outcome(temp.path(), b"referenced").unwrap();
        let (workspace, _, _) = storage
            .create_workspace("Publication cleanup", "owner@example.test")
            .unwrap();
        storage
            .create_file_with_content_bytes(
                CreateFileRequest {
                    workspace_id: workspace.id,
                    parent_id: None,
                    name: "kept.txt".to_string(),
                    kind: FileKind::File,
                    content: None,
                    path: None,
                },
                Some(referenced.hash.clone()),
                referenced.size as i64,
            )
            .unwrap();
        drop(shared);

        let exclusive = BlobLifecycleLock::acquire_exclusive(temp.path()).unwrap();
        remove_created_unreferenced(
            &storage,
            temp.path(),
            &[orphan.clone(), duplicate, referenced.clone()],
        )
        .unwrap();
        drop(exclusive);

        assert!(!blob::blob_file_path(temp.path(), &orphan.hash)
            .unwrap()
            .exists());
        assert!(blob::blob_file_path(temp.path(), &referenced.hash)
            .unwrap()
            .exists());
    }

    #[tokio::test]
    async fn dropping_a_guard_detaches_cleanup_until_other_publishers_exit() {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let blocker = BlobLifecycleLock::acquire_shared(temp.path()).unwrap();
        let mut pending = PendingBlobPublications {
            data_dir: temp.path().to_path_buf(),
            storage,
            shared_lock: Some(BlobLifecycleLock::acquire_shared(temp.path()).unwrap()),
            publications: Vec::new(),
            runtime: tokio::runtime::Handle::current(),
        };
        let orphan = pending.put_bytes(b"cancelled orphan").unwrap();
        let orphan_path = blob::blob_file_path(temp.path(), &orphan.hash).unwrap();
        drop(pending);
        assert!(orphan_path.exists());
        drop(blocker);

        for _ in 0..100 {
            if !orphan_path.exists() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("detached blob compensation did not remove the orphan");
    }
}
