use chrono::Utc;
use rusqlite::{params, OptionalExtension, Transaction};
use uuid::Uuid;

use crate::{
    error::ApiResult,
    model::{DriveFile, FileKind},
};

use super::MAX_DERIVED_INPUT_BYTES;

mod bounds;
mod recovery;
mod restore;
#[cfg(test)]
pub(super) use bounds::normalize_restored_jobs;
pub(super) use bounds::{bound_existing_queued_jobs, prune_terminal_background_jobs};
#[cfg(test)]
pub(super) use recovery::MAX_BACKGROUND_JOB_ATTEMPTS;
pub(super) use restore::admit_restored_queued_job_in_tx;

const FILE_DERIVATION_KINDS: [&str; 2] = ["search_index", "preview_text"];

/// Bounds apply to queued, not running, work. A running job has already been
/// atomically claimed and can read at most `MAX_DERIVED_INPUT_BYTES`.
pub(super) const MAX_PENDING_BACKGROUND_JOBS: i64 = 4_096;
pub(super) const MAX_PENDING_BACKGROUND_JOBS_PER_WORKSPACE: i64 = 512;
pub(super) const MAX_PENDING_BACKGROUND_JOB_BYTES: i64 = 4 * 1024 * 1024 * 1024;
pub(super) const MAX_PENDING_BACKGROUND_JOB_BYTES_PER_WORKSPACE: i64 = 512 * 1024 * 1024;

const DEFAULT_PENDING_JOB_LIMITS: PendingJobLimits = PendingJobLimits {
    global_count: MAX_PENDING_BACKGROUND_JOBS,
    workspace_count: MAX_PENDING_BACKGROUND_JOBS_PER_WORKSPACE,
    global_bytes: MAX_PENDING_BACKGROUND_JOB_BYTES,
    workspace_bytes: MAX_PENDING_BACKGROUND_JOB_BYTES_PER_WORKSPACE,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct PendingJobLimits {
    pub(super) global_count: i64,
    pub(super) workspace_count: i64,
    pub(super) global_bytes: i64,
    pub(super) workspace_bytes: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BackgroundJobAdmission {
    Queued,
    Coalesced,
    DroppedAtCapacity,
    Ignored,
}

#[derive(Debug, Clone, Copy)]
struct PendingJobTotals {
    count: i64,
    bytes: i64,
}

/// Queue both file-derived products while the caller's mutation transaction is
/// open. Imports and folder templates use this to commit the file tree,
/// durable queue admission, and receipt as one state transition.
pub(super) fn enqueue_file_background_jobs_in_tx(
    tx: &Transaction<'_>,
    file: &DriveFile,
) -> ApiResult<BackgroundJobAdmission> {
    enqueue_background_jobs_in_tx(tx, file, &FILE_DERIVATION_KINDS, DEFAULT_PENDING_JOB_LIMITS)
}

#[cfg(test)]
pub(super) fn enqueue_background_job_in_tx(
    tx: &Transaction<'_>,
    file: &DriveFile,
    kind: &str,
) -> ApiResult<BackgroundJobAdmission> {
    enqueue_background_jobs_in_tx(tx, file, &[kind], DEFAULT_PENDING_JOB_LIMITS)
}

#[cfg(test)]
fn enqueue_file_background_jobs_in_tx_with_limits(
    tx: &Transaction<'_>,
    file: &DriveFile,
    limits: PendingJobLimits,
) -> ApiResult<BackgroundJobAdmission> {
    enqueue_background_jobs_in_tx(tx, file, &FILE_DERIVATION_KINDS, limits)
}

fn enqueue_background_jobs_in_tx(
    tx: &Transaction<'_>,
    file: &DriveFile,
    kinds: &[&str],
    limits: PendingJobLimits,
) -> ApiResult<BackgroundJobAdmission> {
    if !matches!(file.kind, FileKind::File) || kinds.is_empty() {
        return Ok(BackgroundJobAdmission::Ignored);
    }

    let estimated_bytes = bounded_job_bytes(file);
    let new_count = i64::try_from(kinds.len()).unwrap_or(i64::MAX);
    let new_bytes = estimated_bytes.saturating_mul(new_count);
    let mut existing_count = 0_i64;
    let mut existing_bytes = 0_i64;
    for kind in kinds {
        let existing = tx
            .query_row(
                "SELECT estimated_bytes
                 FROM background_jobs
                 WHERE status = 'queued' AND kind = ?1
                   AND workspace_id = ?2 AND file_id = ?3",
                params![kind, &file.workspace_id, &file.id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if let Some(bytes) = existing {
            existing_count += 1;
            existing_bytes = existing_bytes.saturating_add(bytes.max(1));
        }
    }

    let global = pending_job_totals(tx, None)?;
    let workspace = pending_job_totals(tx, Some(&file.workspace_id))?;
    let projected_global =
        replace_pending_totals(global, existing_count, existing_bytes, new_count, new_bytes);
    let projected_workspace = replace_pending_totals(
        workspace,
        existing_count,
        existing_bytes,
        new_count,
        new_bytes,
    );
    if projected_global.count > limits.global_count
        || projected_global.bytes > limits.global_bytes
        || projected_workspace.count > limits.workspace_count
        || projected_workspace.bytes > limits.workspace_bytes
    {
        // An older queued job would derive stale metadata from a previous
        // revision. Delete exactly this file's coalesced jobs rather than leave
        // undercounted or stale work behind when admission is saturated.
        for kind in kinds {
            tx.execute(
                "DELETE FROM background_jobs
                 WHERE status = 'queued' AND kind = ?1
                   AND workspace_id = ?2 AND file_id = ?3",
                params![kind, &file.workspace_id, &file.id],
            )?;
        }
        return Ok(BackgroundJobAdmission::DroppedAtCapacity);
    }

    let now = Utc::now().to_rfc3339();
    for kind in kinds {
        let updated = tx.execute(
            "UPDATE background_jobs
             SET estimated_bytes = ?1, updated_at = ?2
             WHERE status = 'queued' AND kind = ?3
               AND workspace_id = ?4 AND file_id = ?5",
            params![estimated_bytes, &now, kind, &file.workspace_id, &file.id],
        )?;
        if updated == 0 {
            tx.execute(
                "INSERT INTO background_jobs
                    (id, kind, status, workspace_id, file_id, estimated_bytes,
                     attempts, last_error, created_at, updated_at, started_at, finished_at)
                 VALUES (?1, ?2, 'queued', ?3, ?4, ?5, 0, NULL, ?6, ?6, NULL, NULL)",
                params![
                    Uuid::now_v7().to_string(),
                    kind,
                    &file.workspace_id,
                    &file.id,
                    estimated_bytes,
                    &now
                ],
            )?;
        }
    }

    Ok(if existing_count == new_count {
        BackgroundJobAdmission::Coalesced
    } else {
        BackgroundJobAdmission::Queued
    })
}

fn bounded_job_bytes(file: &DriveFile) -> i64 {
    file.size_bytes
        .unwrap_or(1)
        .max(1)
        .min(MAX_DERIVED_INPUT_BYTES as i64)
}

fn pending_job_totals(
    tx: &Transaction<'_>,
    workspace_id: Option<&str>,
) -> rusqlite::Result<PendingJobTotals> {
    let (count, bytes) = match workspace_id {
        Some(workspace_id) => tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(estimated_bytes), 0)
             FROM background_jobs
             WHERE status = 'queued' AND workspace_id = ?1",
            params![workspace_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?,
        None => tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(estimated_bytes), 0)
             FROM background_jobs
             WHERE status = 'queued'",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?,
    };
    Ok(PendingJobTotals {
        count,
        bytes: bytes.max(0),
    })
}

fn replace_pending_totals(
    totals: PendingJobTotals,
    existing_count: i64,
    existing_bytes: i64,
    new_count: i64,
    new_bytes: i64,
) -> PendingJobTotals {
    PendingJobTotals {
        count: totals
            .count
            .saturating_sub(existing_count)
            .saturating_add(new_count),
        bytes: totals
            .bytes
            .saturating_sub(existing_bytes)
            .saturating_add(new_bytes),
    }
}

#[cfg(test)]
mod tests;
