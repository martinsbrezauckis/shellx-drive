#[cfg(test)]
use rusqlite::Transaction;
use rusqlite::{params, Connection};

#[cfg(test)]
use crate::error::ApiResult;

use super::{
    MAX_PENDING_BACKGROUND_JOBS, MAX_PENDING_BACKGROUND_JOBS_PER_WORKSPACE,
    MAX_PENDING_BACKGROUND_JOB_BYTES, MAX_PENDING_BACKGROUND_JOB_BYTES_PER_WORKSPACE,
};

const TERMINAL_JOBS_PER_WORKSPACE: i64 = 1_000;

/// Re-estimate and deterministically trim an already-populated queue through
/// the same count and byte ceilings used by live admission.
pub(crate) fn bound_existing_queued_jobs(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE background_jobs
         SET estimated_bytes = MAX(1, MIN(
             COALESCE((SELECT content_bytes FROM files
                       WHERE files.id = background_jobs.file_id), 1),
             33554432
         ))
         WHERE status = 'queued'",
        [],
    )?;
    conn.execute(
        "DELETE FROM background_jobs WHERE id IN (
             SELECT id FROM (
                 SELECT id, ROW_NUMBER() OVER (
                     PARTITION BY COALESCE(workspace_id, '')
                     ORDER BY created_at ASC, id ASC
                 ) AS workspace_rank
                 FROM background_jobs WHERE status = 'queued'
             ) WHERE workspace_rank > ?1
         )",
        params![MAX_PENDING_BACKGROUND_JOBS_PER_WORKSPACE],
    )?;
    conn.execute(
        "DELETE FROM background_jobs WHERE id IN (
             SELECT id FROM (
                 SELECT id, SUM(estimated_bytes) OVER (
                     PARTITION BY COALESCE(workspace_id, '')
                     ORDER BY created_at ASC, id ASC
                     ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
                 ) AS workspace_bytes
                 FROM background_jobs WHERE status = 'queued'
             ) WHERE workspace_bytes > ?1
         )",
        params![MAX_PENDING_BACKGROUND_JOB_BYTES_PER_WORKSPACE],
    )?;
    conn.execute(
        "DELETE FROM background_jobs
         WHERE status = 'queued' AND id NOT IN (
             SELECT id FROM background_jobs WHERE status = 'queued'
             ORDER BY created_at ASC, id ASC LIMIT ?1
         )",
        params![MAX_PENDING_BACKGROUND_JOBS],
    )?;
    conn.execute(
        "DELETE FROM background_jobs WHERE id IN (
             SELECT id FROM (
                 SELECT id, SUM(estimated_bytes) OVER (
                     ORDER BY created_at ASC, id ASC
                     ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
                 ) AS global_bytes
                 FROM background_jobs WHERE status = 'queued'
             ) WHERE global_bytes > ?1
         )",
        params![MAX_PENDING_BACKGROUND_JOB_BYTES],
    )?;
    Ok(())
}

pub(crate) fn prune_terminal_background_jobs(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM background_jobs WHERE id IN (
           SELECT id FROM (
             SELECT id,
                    ROW_NUMBER() OVER (
                      PARTITION BY workspace_id
                      ORDER BY updated_at DESC, id DESC
                    ) AS terminal_rank
             FROM background_jobs
             WHERE status IN ('succeeded', 'failed', 'skipped')
           )
           WHERE terminal_rank > ?1
         )",
        params![TERMINAL_JOBS_PER_WORKSPACE],
    )?;
    Ok(())
}

/// Operational queue state is not backup authority. Retain only supported,
/// current pending subjects and reset runtime claim state before bounding it.
#[cfg(test)]
pub(crate) fn normalize_restored_jobs(tx: &Transaction<'_>) -> ApiResult<()> {
    tx.execute(
        "DELETE FROM background_jobs
         WHERE status != 'queued'
            OR kind NOT IN ('search_index', 'preview_text')
            OR workspace_id IS NULL OR file_id IS NULL
            OR NOT EXISTS (
                SELECT 1 FROM files
                WHERE files.id = background_jobs.file_id
                  AND files.workspace_id = background_jobs.workspace_id
                  AND files.kind = 'file' AND files.trashed = 0
            )",
        [],
    )?;
    tx.execute(
        "UPDATE background_jobs
         SET attempts = 0, last_error = NULL, started_at = NULL, finished_at = NULL",
        [],
    )?;
    bound_existing_queued_jobs(tx)?;
    Ok(())
}
