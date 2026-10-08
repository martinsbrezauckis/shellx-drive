use crate::{
    error::ApiResult,
    model::{UploadPreflightFile, UploadPreflightResponse, WorkspaceUsage},
};

use super::{AppState, PartitionedPermit};

impl AppState {
    pub(crate) async fn run_metadata_planning_retained<T>(
        &self,
        actor_email: &str,
        work: impl FnOnce() -> ApiResult<T> + Send + 'static,
    ) -> ApiResult<(T, PartitionedPermit)>
    where
        T: Send + 'static,
    {
        self.metadata_planning
            .run_blocking_retained(actor_email, work)
            .await
    }

    /// Run metadata planning outside Tokio workers while retaining the shared
    /// global and per-actor permit until the synchronous work actually exits.
    pub(crate) async fn run_metadata_planning<T>(
        &self,
        actor_email: &str,
        work: impl FnOnce() -> ApiResult<T> + Send + 'static,
    ) -> ApiResult<T>
    where
        T: Send + 'static,
    {
        self.metadata_planning
            .run_blocking(actor_email, work)
            .await?
    }

    /// Run every reader-reachable workspace usage traversal behind the shared
    /// global and per-actor planning governor. `run_blocking` owns its permit
    /// until SQLite work exits even when the HTTP caller is cancelled.
    pub(crate) async fn run_workspace_usage(
        &self,
        workspace_id: String,
        actor_email: &str,
    ) -> ApiResult<WorkspaceUsage> {
        let storage = self.storage.clone();
        self.run_metadata_planning(actor_email, move || storage.workspace_usage(&workspace_id))
            .await
    }

    pub(crate) async fn run_upload_preflight(
        &self,
        workspace_id: String,
        parent_id: Option<String>,
        files: Vec<UploadPreflightFile>,
        requested_bytes: i64,
        actor_email: &str,
    ) -> ApiResult<UploadPreflightResponse> {
        let storage = self.storage.clone();
        self.run_metadata_planning(actor_email, move || {
            storage.upload_preflight(&workspace_id, parent_id.as_deref(), &files, requested_bytes)
        })
        .await
    }

    pub(crate) async fn run_workspace_usage_list(
        &self,
        actor_email: &str,
    ) -> ApiResult<Vec<WorkspaceUsage>> {
        let storage = self.storage.clone();
        self.run_metadata_planning(actor_email, move || storage.list_workspace_usage())
            .await
    }
}
