use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::Serialize;

use super::{authorization, Storage};
use crate::{
    auth::{token_hash, Actor, DriveCredential},
    error::ApiResult,
};

#[derive(Debug, Clone, Serialize)]
pub struct DebugActivitySummary {
    pub activity_ref: String,
    pub kind: String,
    pub actor_ref: String,
    pub target_ref: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugWorkspaceSummary {
    pub workspace_id: String,
    pub storage_mode: String,
    pub archived: bool,
    pub members: i64,
    pub active_members: i64,
    pub files: i64,
    pub folders: i64,
    pub current_file_bytes: i64,
    pub quota_bytes: Option<i64>,
    pub public_links_enabled: bool,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugAppTokenSummary {
    pub token_ref: String,
    pub label_present: bool,
    pub actor_ref: String,
    pub workspace_ids: Vec<String>,
    pub expires_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugSyncConflictSummary {
    pub workspace_id: String,
    pub file_ref: String,
    pub source_file_ref: String,
    pub conflict_of_revision: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugImportSummary {
    pub operation_ref: String,
    pub kind: String,
    pub actor_ref: String,
    pub workspace_id: Option<String>,
    pub status: String,
    pub entries: i64,
    pub files: i64,
    pub folders: i64,
    pub bytes: i64,
    pub error_code: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

impl Storage {
    pub(crate) fn e2e_expire_workspace_invitation_authorized(
        &self,
        invitation_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<bool> {
        let expired_at = "2000-01-01T00:00:00Z";
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let changed = tx.execute(
            "UPDATE workspace_invitations SET expires_at = ?1, updated_at = ?1
             WHERE id = ?2 AND status = 'pending'",
            params![expired_at, invitation_id],
        )? == 1;
        super::email_outbox::purge_inactive_delivery_rows_locked(
            &tx,
            &chrono::Utc::now().to_rfc3339(),
        )?;
        tx.commit()?;
        Ok(changed)
    }

    pub(crate) fn e2e_expire_password_reset_authorized(
        &self,
        reset_token_hash: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<bool> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let changed = tx.execute(
            "UPDATE password_reset_tokens SET expires_at = '2000-01-01T00:00:00Z'
             WHERE token_hash = ?1 AND used_at IS NULL",
            params![reset_token_hash],
        )? == 1;
        tx.commit()?;
        Ok(changed)
    }

    pub fn debug_activity_summaries(
        &self,
        limit: i64,
        before: Option<&str>,
        kind: Option<&str>,
    ) -> ApiResult<(i64, Vec<DebugActivitySummary>)> {
        let conn = self.conn.lock().unwrap();
        let total = conn.query_row(
            "SELECT COUNT(*) FROM activity
             WHERE (?1 IS NULL OR created_at < ?1)
               AND (?2 IS NULL OR kind = ?2)",
            params![before, kind],
            |row| row.get(0),
        )?;
        let mut statement = conn.prepare(
            "SELECT id, kind, actor, target_id, created_at FROM activity
             WHERE (?1 IS NULL OR created_at < ?1)
               AND (?2 IS NULL OR kind = ?2)
             ORDER BY created_at DESC, id DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(params![before, kind, limit], |row| {
            let id: String = row.get(0)?;
            let actor: String = row.get(2)?;
            let target_id: Option<String> = row.get(3)?;
            Ok(DebugActivitySummary {
                activity_ref: opaque_ref("activity", &id),
                kind: row.get(1)?,
                actor_ref: opaque_ref("actor", &actor),
                target_ref: target_id
                    .as_deref()
                    .map(|value| opaque_ref("target", value)),
                created_at: row.get(4)?,
            })
        })?;
        Ok((total, rows.collect::<rusqlite::Result<Vec<_>>>()?))
    }

    pub fn debug_workspace_summaries(
        &self,
        limit: i64,
    ) -> ApiResult<(i64, Vec<DebugWorkspaceSummary>)> {
        let conn = self.conn.lock().unwrap();
        let total = conn.query_row("SELECT COUNT(*) FROM workspaces", [], |row| row.get(0))?;
        let now = chrono::Utc::now().to_rfc3339();
        let mut statement = conn.prepare(
            "SELECT w.id, w.storage_mode, w.archived_at IS NOT NULL,
                    (SELECT COUNT(*) FROM workspace_members wm WHERE wm.workspace_id = w.id),
                    (SELECT COUNT(*) FROM workspace_members wm
                     WHERE wm.workspace_id = w.id
                       AND (wm.expires_at IS NULL OR wm.expires_at > ?1)),
                    (SELECT COUNT(*) FROM files f
                     WHERE f.workspace_id = w.id AND f.trashed = 0 AND f.kind = 'file'),
                    (SELECT COUNT(*) FROM files f
                     WHERE f.workspace_id = w.id AND f.trashed = 0 AND f.kind = 'folder'),
                    (SELECT COALESCE(SUM(f.content_bytes), 0) FROM files f
                     WHERE f.workspace_id = w.id AND f.trashed = 0 AND f.kind = 'file'),
                    wp.quota_bytes, COALESCE(wp.public_links_enabled, 1),
                    COALESCE(w.updated_at, w.created_at)
             FROM workspaces w
             LEFT JOIN workspace_policies wp ON wp.workspace_id = w.id
             ORDER BY COALESCE(w.updated_at, w.created_at) DESC, w.id DESC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![now, limit], |row| {
            Ok(DebugWorkspaceSummary {
                workspace_id: row.get(0)?,
                storage_mode: row.get(1)?,
                archived: row.get(2)?,
                members: row.get(3)?,
                active_members: row.get(4)?,
                files: row.get(5)?,
                folders: row.get(6)?,
                current_file_bytes: row.get(7)?,
                quota_bytes: row.get(8)?,
                public_links_enabled: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?;
        Ok((total, rows.collect::<rusqlite::Result<Vec<_>>>()?))
    }

    pub fn debug_app_token_summaries(
        &self,
        limit: i64,
    ) -> ApiResult<(i64, Vec<DebugAppTokenSummary>)> {
        let conn = self.conn.lock().unwrap();
        let total = conn.query_row(
            "SELECT COUNT(*) FROM app_tokens WHERE publication_pending = 0",
            [],
            |row| row.get(0),
        )?;
        let mut statement = conn.prepare(
            "SELECT id, label, actor_email, workspace_ids_json, expires_at,
                    last_used_at, revoked_at, created_at
             FROM app_tokens
             WHERE publication_pending = 0
             ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit], |row| {
            let id: String = row.get(0)?;
            let label: String = row.get(1)?;
            let actor: String = row.get(2)?;
            let workspace_ids_json: String = row.get(3)?;
            let revoked_at: Option<String> = row.get(6)?;
            Ok(DebugAppTokenSummary {
                token_ref: opaque_ref("app-token", &id),
                label_present: !label.trim().is_empty(),
                actor_ref: opaque_ref("actor", &actor),
                workspace_ids: serde_json::from_str(&workspace_ids_json).unwrap_or_default(),
                expires_at: row.get(4)?,
                last_used_at: row.get(5)?,
                revoked: revoked_at.is_some(),
                revoked_at,
                created_at: row.get(7)?,
            })
        })?;
        Ok((total, rows.collect::<rusqlite::Result<Vec<_>>>()?))
    }

    pub fn debug_sync_conflict_summaries(
        &self,
        limit: i64,
    ) -> ApiResult<(i64, Vec<DebugSyncConflictSummary>)> {
        let conn = self.conn.lock().unwrap();
        let predicate = "fr.conflict_of_revision IS NOT NULL
                         AND fr.conflict_of_file_id IS NOT NULL AND f.trashed = 0";
        let total = conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM file_revisions fr JOIN files f ON f.id = fr.file_id WHERE {predicate}"
            ),
            [],
            |row| row.get(0),
        )?;
        let mut statement = conn.prepare(&format!(
            "SELECT f.workspace_id, f.id, fr.conflict_of_file_id,
                    fr.conflict_of_revision, fr.created_at
             FROM file_revisions fr JOIN files f ON f.id = fr.file_id
             WHERE {predicate} ORDER BY fr.created_at DESC LIMIT ?1"
        ))?;
        let rows = statement.query_map(params![limit], |row| {
            let file_id: String = row.get(1)?;
            let source_id: String = row.get(2)?;
            Ok(DebugSyncConflictSummary {
                workspace_id: row.get(0)?,
                file_ref: opaque_ref("file", &file_id),
                source_file_ref: opaque_ref("file", &source_id),
                conflict_of_revision: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        Ok((total, rows.collect::<rusqlite::Result<Vec<_>>>()?))
    }

    pub fn debug_import_summaries(&self, limit: i64) -> ApiResult<(i64, Vec<DebugImportSummary>)> {
        let conn = self.conn.lock().unwrap();
        let total = conn.query_row("SELECT COUNT(*) FROM import_runs", [], |row| row.get(0))?;
        let mut statement = conn.prepare(
            "SELECT id, kind, actor, workspace_id, status, entries, files,
                    folders, bytes, error_code, created_at, updated_at, completed_at
             FROM import_runs
             ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit], |row| {
            let id: String = row.get(0)?;
            let actor: String = row.get(2)?;
            Ok(DebugImportSummary {
                operation_ref: opaque_ref("import", &id),
                kind: row.get(1)?,
                actor_ref: opaque_ref("actor", &actor),
                workspace_id: row.get(3)?,
                status: row.get(4)?,
                entries: row.get(5)?,
                files: row.get(6)?,
                folders: row.get(7)?,
                bytes: row.get(8)?,
                error_code: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
                completed_at: row.get(12)?,
            })
        })?;
        Ok((total, rows.collect::<rusqlite::Result<Vec<_>>>()?))
    }

    pub fn debug_active_import_run_count(&self) -> ApiResult<i64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM import_runs WHERE status = 'running'",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn debug_referenced_blob_hashes(&self, limit: i64) -> ApiResult<(i64, Vec<String>)> {
        let conn = self.conn.lock().unwrap();
        let union = "SELECT content_hash AS hash FROM files WHERE content_hash IS NOT NULL
                     UNION SELECT cover_hash FROM files WHERE cover_hash IS NOT NULL
                     UNION SELECT content_hash FROM file_revisions WHERE content_hash IS NOT NULL
                     UNION SELECT thumbnail_hash FROM file_previews WHERE thumbnail_hash IS NOT NULL";
        let total = conn.query_row(&format!("SELECT COUNT(*) FROM ({union})"), [], |row| {
            row.get(0)
        })?;
        let mut statement = conn.prepare(&format!("{union} ORDER BY hash ASC LIMIT ?1"))?;
        let rows = statement.query_map(params![limit], |row| row.get(0))?;
        Ok((total, rows.collect::<rusqlite::Result<Vec<_>>>()?))
    }

    pub fn debug_last_import_receipt_at(&self) -> ApiResult<Option<String>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT created_at FROM import_runs
                 ORDER BY created_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?)
    }
}

pub(super) fn opaque_ref(prefix: &str, value: &str) -> String {
    format!("{prefix}-{}", &token_hash(value)[..12])
}
