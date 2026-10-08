use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};

use axum::http::{header, HeaderMap};
use uuid::Uuid;

use crate::{
    error::{ApiError, ApiResult},
    server::AppState,
};

use super::MAX_WEBDAV_PUT_BYTES;

#[cfg(test)]
mod tests;

pub(super) struct StreamLimits {
    remaining_quota: Option<u64>,
}

impl StreamLimits {
    pub(super) fn for_workspace(state: &AppState, workspace_id: &str) -> ApiResult<Self> {
        let remaining_quota = state
            .storage
            .workspace_usage(workspace_id)?
            .remaining_bytes
            .map(|value| u64::try_from(value).unwrap_or(0));
        Ok(Self { remaining_quota })
    }

    pub(super) fn check(&self, received: u64) -> ApiResult<i64> {
        if received > MAX_WEBDAV_PUT_BYTES {
            return Err(ApiError::PayloadTooLarge(format!(
                "WebDAV PUT exceeds {MAX_WEBDAV_PUT_BYTES} bytes"
            )));
        }
        let quota_charge = received.max(1);
        if self
            .remaining_quota
            .is_some_and(|remaining| quota_charge > remaining)
        {
            return Err(ApiError::Validation(
                "quota exceeded while streaming WebDAV PUT".to_string(),
            ));
        }
        i64::try_from(received).map_err(|_| {
            ApiError::PayloadTooLarge("WebDAV PUT exceeds supported range".to_string())
        })
    }
}

pub(super) fn content_length(headers: &HeaderMap) -> ApiResult<Option<u64>> {
    let mut declared = None;
    for value in &headers.get_all(header::CONTENT_LENGTH) {
        let value = value
            .to_str()
            .map_err(|_| ApiError::Validation("invalid WebDAV Content-Length".to_string()))?
            .parse::<u64>()
            .map_err(|_| ApiError::Validation("invalid WebDAV Content-Length".to_string()))?;
        if declared.replace(value).is_some_and(|prior| prior != value) {
            return Err(ApiError::Validation(
                "conflicting WebDAV Content-Length headers".to_string(),
            ));
        }
    }
    Ok(declared)
}

pub(super) struct DavStagingFile {
    path: PathBuf,
    open_file: Option<std::fs::File>,
}

impl DavStagingFile {
    pub(super) async fn create(state: &AppState) -> ApiResult<Self> {
        Self::create_in_directory(state.data_dir().join("webdav-staging")).await
    }

    async fn create_in_directory(directory: PathBuf) -> ApiResult<Self> {
        crate::fs_private::create_dir_all_private(&directory)?;
        crate::fs_private::set_dir_private(&directory)?;
        let path = directory.join(format!("{}.part", Uuid::new_v4().simple()));
        // The worker owns cleanup even when its request is cancelled before
        // the join handle returns its already-created staging file.
        tokio::task::spawn_blocking(move || create_private_file(&path))
            .await
            .map_err(|_| ApiError::Maintenance("WebDAV staging worker failed".to_string()))?
            .map_err(Into::into)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn take_open_file(&mut self) -> std::fs::File {
        self.open_file.take().expect("staging file exists")
    }
}

impl Drop for DavStagingFile {
    fn drop(&mut self) {
        let _ = self.open_file.take();
        if let Err(error) = std::fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(%error, "WebDAV staging cleanup failed");
            }
        }
    }
}

pub(super) struct StagedDavBody {
    pub(super) staging: DavStagingFile,
    pub(super) size: u64,
    pub(super) hash: String,
}

fn create_private_file(path: &Path) -> std::io::Result<DavStagingFile> {
    create_private_file_with(path, crate::fs_private::set_file_private)
}

fn create_private_file_with(
    path: &Path,
    set_private: impl FnOnce(&Path) -> std::io::Result<()>,
) -> std::io::Result<DavStagingFile> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path)?;
    let staging = DavStagingFile {
        path: path.to_path_buf(),
        open_file: Some(file),
    };
    set_private(path)?;
    Ok(staging)
}
