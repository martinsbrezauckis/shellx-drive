use axum::Json;

use crate::{
    error::ApiResult, model::UploadChunkResponse, routes::blob_publication::PendingBlobPublications,
};

/// Owns the publication guard until the async caller can complete or compensate
/// it. If the caller is cancelled, dropping this outcome retains the guard's
/// existing detached-cleanup behavior.
pub(super) struct UploadChunkWork {
    pub(super) publications: Option<PendingBlobPublications>,
    pub(super) result: ApiResult<Json<UploadChunkResponse>>,
}

impl UploadChunkWork {
    pub(super) async fn finish(self) -> ApiResult<Json<UploadChunkResponse>> {
        match self.publications {
            Some(publications) => publications.finish(self.result).await,
            None => self.result,
        }
    }
}
