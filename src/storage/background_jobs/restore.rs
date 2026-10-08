use rusqlite::{params, OptionalExtension, Transaction};

use crate::error::ApiResult;

use super::{
    enqueue_background_jobs_in_tx, BackgroundJobAdmission, DEFAULT_PENDING_JOB_LIMITS,
    FILE_DERIVATION_KINDS,
};

/// Re-admit supported pending derived work without trusting archived claim
/// state or byte estimates.
pub(crate) fn admit_restored_queued_job_in_tx(
    tx: &Transaction<'_>,
    kind: &str,
    status: &str,
    workspace_id: &str,
    file_id: &str,
) -> ApiResult<BackgroundJobAdmission> {
    if status != "queued" || !FILE_DERIVATION_KINDS.contains(&kind) {
        return Ok(BackgroundJobAdmission::Ignored);
    }
    let file = tx
        .query_row(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed,
                    starred, content_hash, created_at, updated_at, content_bytes,
                    cover_hash
             FROM files WHERE id = ?1 AND workspace_id = ?2",
            params![file_id, workspace_id],
            super::super::row_to_file,
        )
        .optional()?;
    let Some(file) = file.filter(|file| !file.trashed) else {
        return Ok(BackgroundJobAdmission::Ignored);
    };
    enqueue_background_jobs_in_tx(tx, &file, &[kind], DEFAULT_PENDING_JOB_LIMITS)
}
