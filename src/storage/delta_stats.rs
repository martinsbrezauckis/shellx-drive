use rusqlite::{params, Connection, Transaction, TransactionBehavior};

use super::{DeltaWriteStats, Storage};

const MAX_DELTA_STATS_PER_FILE: i64 = 512;
const MAX_DELTA_STATS_PER_WORKSPACE: i64 = 4_096;
const MAX_DELTA_STATS_GLOBAL: i64 = 16_384;

#[cfg(test)]
mod tests;

impl Storage {
    /// Telemetry is derived, bounded history. A file mutation has already
    /// committed when this runs, so persistence failure must not report that
    /// successful mutation as failed or invite a duplicate retry.
    pub(super) fn retain_delta_stats_best_effort(&self, stats: &DeltaWriteStats) {
        let result = (|| -> rusqlite::Result<()> {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT INTO delta_sync_writes (
                    id, file_id, workspace_id, actor_email, base_revision, new_revision,
                    chunk_size, chunks_total, chunks_reused, uploaded_bytes,
                    reconstructed_bytes, content_sha256, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    &stats.id,
                    &stats.file_id,
                    &stats.workspace_id,
                    &stats.actor_email,
                    stats.base_revision,
                    stats.new_revision,
                    stats.chunk_size as i64,
                    stats.chunks_total as i64,
                    stats.chunks_reused as i64,
                    stats.uploaded_bytes,
                    stats.reconstructed_bytes,
                    &stats.content_sha256,
                    &stats.created_at,
                ],
            )?;
            prune_current_partitions(&tx, &stats.file_id, &stats.workspace_id)?;
            tx.commit()
        })();
        if result.is_err() {
            // No SQLite exception, actor, content, or credential enters logs.
            tracing::warn!(
                code = "delta_stats_retention_failed",
                "delta sync statistics were not retained"
            );
        }
    }
}

fn prune_current_partitions(
    tx: &Transaction<'_>,
    file_id: &str,
    workspace_id: &str,
) -> rusqlite::Result<()> {
    tx.execute(
        "DELETE FROM delta_sync_writes WHERE id IN (
            SELECT id FROM delta_sync_writes WHERE file_id = ?1
            ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?2)",
        params![file_id, MAX_DELTA_STATS_PER_FILE],
    )?;
    tx.execute(
        "DELETE FROM delta_sync_writes WHERE id IN (
            SELECT id FROM delta_sync_writes WHERE workspace_id = ?1
            ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?2)",
        params![workspace_id, MAX_DELTA_STATS_PER_WORKSPACE],
    )?;
    prune_global(tx)
}

fn prune_global(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute(
        "DELETE FROM delta_sync_writes WHERE id IN (
            SELECT id FROM delta_sync_writes ORDER BY created_at DESC, id DESC
            LIMIT -1 OFFSET ?1)",
        [MAX_DELTA_STATS_GLOBAL],
    )?;
    Ok(())
}

/// Existing releases retained every write. Reconcile all partitions on open,
/// rather than waiting for an oversized file/workspace to write again.
pub(super) fn reconcile(conn: &mut Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_delta_stats_file_retention
            ON delta_sync_writes(file_id, created_at, id);
         CREATE INDEX IF NOT EXISTS idx_delta_stats_workspace_retention
            ON delta_sync_writes(workspace_id, created_at, id);
         CREATE INDEX IF NOT EXISTS idx_delta_stats_global_retention
            ON delta_sync_writes(created_at, id);",
    )?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "DELETE FROM delta_sync_writes WHERE id IN (
            SELECT id FROM (SELECT id, ROW_NUMBER() OVER (
                PARTITION BY file_id ORDER BY created_at DESC, id DESC) AS retained_rank
                FROM delta_sync_writes) WHERE retained_rank > ?1)",
        [MAX_DELTA_STATS_PER_FILE],
    )?;
    tx.execute(
        "DELETE FROM delta_sync_writes WHERE id IN (
            SELECT id FROM (SELECT id, ROW_NUMBER() OVER (
                PARTITION BY workspace_id ORDER BY created_at DESC, id DESC) AS retained_rank
                FROM delta_sync_writes) WHERE retained_rank > ?1)",
        [MAX_DELTA_STATS_PER_WORKSPACE],
    )?;
    prune_global(&tx)?;
    tx.commit()
}
