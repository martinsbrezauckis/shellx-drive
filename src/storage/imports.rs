use chrono::Utc;
use rusqlite::{params, Connection, TransactionBehavior};
use uuid::Uuid;

mod preview_completion;
mod rclone;
mod rclone_apply;
mod tracking;

pub(crate) use preview_completion::RcloneExportCompletion;
use tracking::bounded_error_code;
pub use tracking::ImportRunTotals;

use super::Storage;
use crate::error::{ApiError, ApiResult};

pub(crate) use rclone_apply::{PreparedRcloneContent, PreparedRcloneEntry};

/// The legacy rclone-v1 JSON export is a small compatibility surface, not a
/// workspace-scale traversal API. The query deliberately fetches one extra row
/// so a larger workspace fails before it is materialized in process memory.
pub const RCLONE_V1_MAX_ACTIVE_EXPORT_ENTRIES: usize = 10_000;
const MAX_RUNNING_IMPORT_RUNS_GLOBAL: i64 = 32;
const MAX_RUNNING_IMPORT_RUNS_PER_ACTOR_WORKSPACE: i64 = 4;
const MAX_TERMINAL_IMPORT_RUNS_GLOBAL: i64 = 10_000;
const MAX_TERMINAL_IMPORT_RUNS_PER_WORKSPACE: i64 = 1_000;

pub(super) fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS import_runs (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            workspace_id TEXT,
            actor TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'interrupted')),
            entries INTEGER NOT NULL DEFAULT 0,
            files INTEGER NOT NULL DEFAULT 0,
            folders INTEGER NOT NULL DEFAULT 0,
            bytes INTEGER NOT NULL DEFAULT 0,
            error_code TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            completed_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_import_runs_created
            ON import_runs(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_import_runs_status
            ON import_runs(status, updated_at DESC);
        "#,
    )
}

impl Storage {
    /// Return the active file tree only when it fits the legacy rclone-v1
    /// export entry contract. This is intentionally a specialized query rather
    /// than an unbounded workspace listing followed by a route-level filter.
    pub fn list_active_files_for_rclone_v1_export(
        &self,
        workspace_id: &str,
    ) -> ApiResult<Vec<crate::model::DriveFile>> {
        let conn = self.conn.lock().unwrap();
        rclone::query_active_files(&conn, workspace_id, RCLONE_V1_MAX_ACTIVE_EXPORT_ENTRIES)
    }

    pub fn start_import_run(
        &self,
        kind: &str,
        actor: &str,
        workspace_id: Option<&str>,
    ) -> ApiResult<String> {
        if !matches!(kind, "rclone_preview" | "rclone_apply" | "rclone_export") {
            return Err(ApiError::Validation(
                "unsupported import/export run kind".to_string(),
            ));
        }
        let id = Uuid::now_v7().to_string();
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM import_runs
             WHERE status <> 'running' AND id NOT IN (
                 SELECT id FROM import_runs WHERE status <> 'running'
                 ORDER BY updated_at DESC, id DESC LIMIT ?1
             )",
            params![MAX_TERMINAL_IMPORT_RUNS_GLOBAL],
        )?;
        tx.execute(
            "DELETE FROM import_runs
             WHERE status <> 'running'
               AND ((workspace_id = ?1) OR (workspace_id IS NULL AND ?1 IS NULL))
               AND id NOT IN (
                 SELECT id FROM import_runs
                 WHERE status <> 'running'
                   AND ((workspace_id = ?1) OR (workspace_id IS NULL AND ?1 IS NULL))
                 ORDER BY updated_at DESC, id DESC LIMIT ?2
               )",
            params![workspace_id, MAX_TERMINAL_IMPORT_RUNS_PER_WORKSPACE],
        )?;
        let running_global: i64 = tx.query_row(
            "SELECT COUNT(*) FROM import_runs WHERE status = 'running'",
            [],
            |row| row.get(0),
        )?;
        let running_partition: i64 = tx.query_row(
            "SELECT COUNT(*) FROM import_runs
             WHERE status = 'running' AND actor = ?1
               AND ((workspace_id = ?2) OR (workspace_id IS NULL AND ?2 IS NULL))",
            params![actor, workspace_id],
            |row| row.get(0),
        )?;
        if running_global >= MAX_RUNNING_IMPORT_RUNS_GLOBAL
            || running_partition >= MAX_RUNNING_IMPORT_RUNS_PER_ACTOR_WORKSPACE
        {
            return Err(ApiError::TooManyRequests);
        }
        tx.execute(
            "INSERT INTO import_runs
                (id, kind, workspace_id, actor, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'running', ?5, ?5)",
            params![id, kind, workspace_id, actor, now],
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn finish_import_run(
        &self,
        id: &str,
        status: &str,
        totals: ImportRunTotals,
        error_code: Option<&str>,
    ) -> ApiResult<()> {
        if !matches!(status, "succeeded" | "failed" | "interrupted") {
            return Err(ApiError::Validation(
                "invalid import/export run status".to_string(),
            ));
        }
        let error_code = error_code.map(bounded_error_code).transpose()?;
        let now = Utc::now().to_rfc3339();
        let changed = self.conn.lock().unwrap().execute(
            "UPDATE import_runs
             SET status = ?1, entries = ?2, files = ?3, folders = ?4,
                 bytes = ?5, error_code = ?6, updated_at = ?7, completed_at = ?7
             WHERE id = ?8 AND status = 'running'",
            params![
                status,
                totals.entries,
                totals.files,
                totals.folders,
                totals.bytes,
                error_code,
                now,
                id,
            ],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ApiError::Conflict)
        }
    }

    pub fn interrupt_running_import_runs(&self) -> ApiResult<usize> {
        let now = Utc::now().to_rfc3339();
        Ok(self.conn.lock().unwrap().execute(
            "UPDATE import_runs
             SET status = 'interrupted', error_code = 'service_restarted',
                 updated_at = ?1, completed_at = ?1
             WHERE status = 'running'",
            params![now],
        )?)
    }
}
