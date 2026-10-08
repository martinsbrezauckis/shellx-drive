use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{FileKind, RcloneBundle, RcloneImportSummary, Receipt},
    routes::content_revalidation::AuthenticatedWorkspacePublication,
    server::AppState,
    storage::{ImportRunTotals, Storage},
};

pub(super) struct ImportRunTracker {
    storage: Storage,
    id: String,
    finished: bool,
}

impl ImportRunTracker {
    pub(super) fn start(
        state: &AppState,
        kind: &str,
        actor: &str,
        workspace_id: &str,
    ) -> ApiResult<Self> {
        Ok(Self {
            storage: state.storage.clone(),
            id: state
                .storage
                .start_import_run(kind, actor, Some(workspace_id))?,
            finished: false,
        })
    }

    pub(super) fn succeed(mut self, totals: ImportRunTotals) -> ApiResult<()> {
        self.storage
            .finish_import_run(&self.id, "succeeded", totals, None)?;
        self.finished = true;
        Ok(())
    }

    pub(super) fn succeed_rclone_export_authorized(
        &mut self,
        publication: &AuthenticatedWorkspacePublication,
        totals: ImportRunTotals,
        statistics_targets: &[(String, String)],
    ) -> ApiResult<()> {
        publication.complete_rclone_export_authorized(&self.id, totals, statistics_targets)?;
        self.finished = true;
        Ok(())
    }

    pub(super) fn succeed_rclone_preview_authorized(
        &mut self,
        workspace_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
        totals: ImportRunTotals,
    ) -> ApiResult<Receipt> {
        let receipt = self.storage.complete_rclone_preview_authorized(
            &self.id,
            workspace_id,
            actor,
            source_credential,
            totals,
        )?;
        self.finished = true;
        Ok(receipt)
    }

    pub(super) fn fail(mut self, error: &ApiError) {
        if self
            .storage
            .finish_import_run(
                &self.id,
                "failed",
                ImportRunTotals::default(),
                Some(error_code(error)),
            )
            .is_ok()
        {
            self.finished = true;
        }
    }
}

impl Drop for ImportRunTracker {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.storage.finish_import_run(
                &self.id,
                "interrupted",
                ImportRunTotals::default(),
                Some("handler_interrupted"),
            );
        }
    }
}

pub(super) fn summary_totals(summary: &RcloneImportSummary) -> ImportRunTotals {
    ImportRunTotals {
        entries: summary.entries,
        files: summary.created_files + summary.updated_files,
        folders: summary.created_folders + summary.existing_folders,
        bytes: summary.estimated_bytes,
    }
}

pub(super) fn bundle_totals(bundle: &RcloneBundle) -> ImportRunTotals {
    ImportRunTotals {
        entries: bundle.entries.len() as i64,
        files: bundle
            .entries
            .iter()
            .filter(|entry| matches!(entry.kind, FileKind::File))
            .count() as i64,
        folders: bundle
            .entries
            .iter()
            .filter(|entry| matches!(entry.kind, FileKind::Folder))
            .count() as i64,
        bytes: bundle
            .entries
            .iter()
            .filter_map(|entry| entry.size)
            .map(|size| size as i64)
            .sum(),
    }
}

fn error_code(error: &ApiError) -> &'static str {
    match error {
        ApiError::Unauthenticated => "unauthenticated",
        ApiError::Forbidden => "forbidden",
        ApiError::NotFound => "not_found",
        ApiError::Conflict => "conflict",
        ApiError::DesktopAgentCancellationRequested => "desktop_agent_cancellation_requested",
        ApiError::DesktopAgentDisconnectCapabilityExpired => {
            "desktop_agent_disconnect_capability_expired"
        }
        ApiError::DesktopAgentDisconnectAuthorizationLost => {
            "desktop_agent_disconnect_authorization_lost"
        }
        ApiError::Locked => "locked",
        ApiError::PreconditionFailed => "precondition_failed",
        ApiError::NotImplemented(_) => "not_implemented",
        ApiError::TooManyRequests => "too_many_requests",
        ApiError::RequestTimeout => "request_timeout",
        ApiError::PayloadTooLarge(_) => "payload_too_large",
        ApiError::SyncRootDiscoveryOverflow => "sync_root_discovery_overflow",
        ApiError::Maintenance(_) => "maintenance",
        ApiError::Validation(_) => "validation_error",
        ApiError::Storage(_) => "storage_error",
        ApiError::Io(_) => "io_error",
    }
}
