use std::collections::HashMap;

use chrono::Utc;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{
        DriveFile, FileKind, Receipt, UploadPreflightConflict, UploadPreflightFile,
        UploadPreflightResponse, UploadSession,
    },
    storage::{
        authorization, checked_stale_upload_cutoff, insert_receipt_rows, new_receipt,
        normalize_relative_upload_path, validate_file_name, Storage,
    },
};

use super::{row_to_upload_session, TERMINAL_UPLOAD_RETENTION_PER_WORKSPACE};
const UPLOAD_HISTORY_PAGE_LIMIT: i64 = 500;

impl Storage {
    pub fn list_upload_sessions(&self) -> ApiResult<Vec<UploadSession>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, actor_email, parent_id, name, total_size, received_bytes, completed, canceled, file_id, created_at, updated_at, canceled_at, path,
                    target_file_id, base_revision, completion_receipt_id,
                    completion_current_revision, duplicate_policy
             FROM upload_sessions ORDER BY updated_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(
            [TERMINAL_UPLOAD_RETENTION_PER_WORKSPACE],
            row_to_upload_session,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_upload_sessions_for_workspace(
        &self,
        workspace_id: &str,
        actor: &Actor,
    ) -> ApiResult<Vec<UploadSession>> {
        self.workspace_storage_mode(workspace_id)?;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, actor_email, parent_id, name, total_size, received_bytes, completed, canceled, file_id, created_at, updated_at, canceled_at, path,
                    target_file_id, base_revision, completion_receipt_id,
                    completion_current_revision, duplicate_policy
             FROM upload_sessions
             WHERE workspace_id = ?1 AND (?2 = 1 OR actor_email = ?3)
             ORDER BY updated_at DESC, id DESC LIMIT ?4",
        )?;
        let rows = stmt.query_map(
            params![
                workspace_id,
                actor.is_admin,
                actor.email,
                UPLOAD_HISTORY_PAGE_LIMIT
            ],
            row_to_upload_session,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn cancel_upload_session_authorized(
        &self,
        upload_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(UploadSession, Receipt)> {
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt("upload.cancel", &actor.email, Some(upload_id));
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session = tx
            .query_row(
                "SELECT id, workspace_id, actor_email, parent_id, name, total_size,
                        received_bytes, completed, canceled, file_id, created_at, updated_at,
                        canceled_at, path, target_file_id, base_revision,
                        completion_receipt_id, completion_current_revision, duplicate_policy
                 FROM upload_sessions WHERE id = ?1",
                params![upload_id],
                row_to_upload_session,
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        if !actor.is_admin && session.actor_email != actor.email {
            return Err(ApiError::NotFound);
        }
        super::admission::ensure_upload_finalizer_permission(
            &tx,
            &session,
            actor,
            source_credential,
        )?;
        if session.completed || session.canceled {
            return Err(ApiError::Conflict);
        }
        if tx.execute(
            "UPDATE upload_sessions
             SET canceled = 1, canceled_at = ?1, updated_at = ?1
             WHERE id = ?2 AND completed = 0 AND canceled = 0",
            params![&now, upload_id],
        )? != 1
        {
            return Err(ApiError::Conflict);
        }
        prune_terminal_upload_sessions_in_tx(&tx, &session.workspace_id)?;
        insert_receipt_rows(&tx, &receipt)?;
        let session = tx.query_row(
            "SELECT id, workspace_id, actor_email, parent_id, name, total_size,
                    received_bytes, completed, canceled, file_id, created_at, updated_at,
                    canceled_at, path, target_file_id, base_revision,
                    completion_receipt_id, completion_current_revision, duplicate_policy
             FROM upload_sessions WHERE id = ?1",
            params![upload_id],
            row_to_upload_session,
        )?;
        tx.commit()?;
        Ok((session, receipt))
    }

    /// Authorize an administrative cleanup and snapshot the sessions that may
    /// be reaped. Callers must still re-check each candidate immediately
    /// before cancellation, after they hold that upload's file lock.
    pub fn stale_upload_cleanup_candidates_authorized(
        &self,
        older_than_seconds: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(Vec<String>, Receipt)> {
        let cutoff = checked_stale_upload_cutoff(older_than_seconds)?;
        let receipt = new_receipt("upload.cleanup", &actor.email, None);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let sessions = stale_upload_session_ids_in_tx(&tx, &cutoff)?;
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((sessions, receipt))
    }

    /// Lists possible stale upload sessions. The result is only a candidate
    /// set: callers must acquire the per-upload staging lock, then use
    /// `reap_stale_upload_session` for the conditional state transition.
    pub fn stale_upload_session_ids(&self, older_than_seconds: i64) -> ApiResult<Vec<String>> {
        let cutoff = checked_stale_upload_cutoff(older_than_seconds)?;
        let conn = self.conn.lock().unwrap();
        stale_upload_session_ids(&conn, &cutoff)
    }

    /// Cancel exactly one still-stale session. The caller holds the matching
    /// staging-file lock, so a finalizer cannot commit a file between this
    /// comparison and the terminal session transition.
    pub fn reap_stale_upload_session(
        &self,
        upload_id: &str,
        older_than_seconds: i64,
    ) -> ApiResult<Option<UploadSession>> {
        crate::upload_ids::require_canonical(upload_id)?;
        let cutoff = checked_stale_upload_cutoff(older_than_seconds)?;
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session = reap_stale_upload_session_in_tx(&tx, upload_id, &cutoff, &now)?;
        tx.commit()?;
        Ok(session)
    }

    /// Revalidate the administrative source credential while holding the same
    /// database write transaction that conditionally cancels this candidate.
    /// The caller must already hold the matching staging-file lock.
    pub fn reap_stale_upload_session_authorized(
        &self,
        upload_id: &str,
        older_than_seconds: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Option<UploadSession>> {
        crate::upload_ids::require_canonical(upload_id)?;
        let cutoff = checked_stale_upload_cutoff(older_than_seconds)?;
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let session = reap_stale_upload_session_in_tx(&tx, upload_id, &cutoff, &now)?;
        tx.commit()?;
        Ok(session)
    }

    pub(crate) fn backfill_upload_session_quota_reservations_in_tx(
        tx: &rusqlite::Transaction<'_>,
    ) -> ApiResult<()> {
        tx.execute(
            "UPDATE upload_sessions
             SET quota_reservation_bytes = CASE
                 WHEN COALESCE(total_size, received_bytes) > 0
                 THEN COALESCE(total_size, received_bytes)
                 ELSE 1 END
             WHERE completed = 0
               AND canceled = 0",
            [],
        )?;
        Ok(())
    }

    pub fn upload_preflight(
        &self,
        workspace_id: &str,
        parent_id: Option<&str>,
        files: &[UploadPreflightFile],
        requested_bytes: i64,
    ) -> ApiResult<UploadPreflightResponse> {
        self.workspace_storage_mode(workspace_id)?;
        if let Some(parent_id) = parent_id {
            self.validate_upload_parent(workspace_id, parent_id)?;
        }

        let mut children: HashMap<(Option<String>, String), Option<DriveFile>> = HashMap::new();

        let mut conflicts = Vec::new();
        for (index, candidate) in files.iter().enumerate() {
            let normalized = match candidate
                .path
                .as_deref()
                .map(str::trim)
                .filter(|path| !path.is_empty())
            {
                Some(path) => normalize_relative_upload_path(path)?,
                None => validate_file_name(&candidate.name)?,
            };
            let mut segments = normalized.split('/').collect::<Vec<_>>();
            let leaf = segments
                .pop()
                .ok_or_else(|| ApiError::Validation("upload path must not be empty".to_string()))?;
            let mut current_parent = parent_id.map(str::to_string);
            let mut path_blocker = None;
            let mut chain_exists = true;
            for segment in segments {
                match cached_active_child(
                    self,
                    &mut children,
                    workspace_id,
                    current_parent.as_deref(),
                    segment,
                )?
                .as_ref()
                {
                    Some(existing) if matches!(existing.kind, FileKind::Folder) => {
                        current_parent = Some(existing.id.clone());
                    }
                    Some(existing) => {
                        path_blocker = Some(existing.id.clone());
                        break;
                    }
                    None => {
                        chain_exists = false;
                        break;
                    }
                }
            }
            if let Some(existing_file_id) = path_blocker {
                conflicts.push(UploadPreflightConflict {
                    index,
                    path: normalized,
                    kind: "path_blocked".to_string(),
                    existing_file_id,
                });
                continue;
            }
            if !chain_exists {
                continue;
            }
            if let Some(existing) = cached_active_child(
                self,
                &mut children,
                workspace_id,
                current_parent.as_deref(),
                leaf,
            )? {
                conflicts.push(UploadPreflightConflict {
                    index,
                    path: normalized,
                    kind: if matches!(existing.kind, FileKind::Folder) {
                        "path_blocked"
                    } else {
                        "duplicate"
                    }
                    .to_string(),
                    existing_file_id: existing.id.clone(),
                });
            }
        }

        let usage = self.workspace_usage(workspace_id)?;
        let fits = usage
            .remaining_bytes
            .is_none_or(|remaining| requested_bytes <= remaining);
        Ok(UploadPreflightResponse {
            workspace_id: workspace_id.to_string(),
            requested_bytes,
            current_file_bytes: Some(usage.current_file_bytes),
            quota_bytes: usage.quota_bytes,
            remaining_bytes: usage.remaining_bytes,
            fits,
            conflicts,
        })
    }

    pub(super) fn validate_upload_parent(
        &self,
        workspace_id: &str,
        parent_id: &str,
    ) -> ApiResult<()> {
        self.validate_parent_chain(workspace_id, parent_id, None)?;
        Ok(())
    }
}

fn reap_stale_upload_session_in_tx(
    tx: &Transaction<'_>,
    upload_id: &str,
    cutoff: &str,
    now: &str,
) -> ApiResult<Option<UploadSession>> {
    let changed = tx.execute(
        "UPDATE upload_sessions
         SET canceled = 1, canceled_at = ?1, updated_at = ?1
         WHERE id = ?2
           AND completed = 0
           AND canceled = 0
           AND julianday(updated_at) <= julianday(?3)",
        params![now, upload_id, cutoff],
    )?;
    if changed == 0 {
        return Ok(None);
    }
    let session = tx.query_row(
        "SELECT id, workspace_id, actor_email, parent_id, name, total_size,
                received_bytes, completed, canceled, file_id, created_at, updated_at,
                canceled_at, path, target_file_id, base_revision,
                completion_receipt_id, completion_current_revision, duplicate_policy
         FROM upload_sessions WHERE id = ?1",
        params![upload_id],
        row_to_upload_session,
    )?;
    prune_terminal_upload_sessions_in_tx(tx, &session.workspace_id)?;
    Ok(Some(session))
}

fn stale_upload_session_ids_in_tx(tx: &Transaction<'_>, cutoff: &str) -> ApiResult<Vec<String>> {
    let mut stmt = tx.prepare(
        "SELECT id
         FROM upload_sessions
         WHERE completed = 0 AND canceled = 0
           AND julianday(updated_at) <= julianday(?1)",
    )?;
    let ids = stmt
        .query_map(params![cutoff], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for id in &ids {
        crate::upload_ids::require_canonical(id)?;
    }
    Ok(ids)
}

fn stale_upload_session_ids(conn: &rusqlite::Connection, cutoff: &str) -> ApiResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT id
         FROM upload_sessions
         WHERE completed = 0 AND canceled = 0
           AND julianday(updated_at) <= julianday(?1)",
    )?;
    let ids = stmt
        .query_map(params![cutoff], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for id in &ids {
        crate::upload_ids::require_canonical(id)?;
    }
    Ok(ids)
}

pub(super) fn prune_terminal_upload_sessions_in_tx(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
) -> ApiResult<()> {
    tx.execute(
        "DELETE FROM upload_sessions
         WHERE workspace_id = ?1
           AND (completed = 1 OR canceled = 1)
           AND id NOT IN (
             SELECT id FROM upload_sessions
             WHERE workspace_id = ?1 AND (completed = 1 OR canceled = 1)
             ORDER BY updated_at DESC, id DESC
             LIMIT ?2
           )",
        params![workspace_id, TERMINAL_UPLOAD_RETENTION_PER_WORKSPACE],
    )?;
    Ok(())
}

fn cached_active_child<'a>(
    storage: &Storage,
    cache: &'a mut HashMap<(Option<String>, String), Option<DriveFile>>,
    workspace_id: &str,
    parent_id: Option<&str>,
    name: &str,
) -> ApiResult<&'a Option<DriveFile>> {
    let key = (parent_id.map(str::to_string), name.to_string());
    if !cache.contains_key(&key) {
        let file = storage.get_active_child_file_by_name(workspace_id, parent_id, name)?;
        cache.insert(key.clone(), file);
    }
    Ok(cache
        .get(&key)
        .expect("cached upload child was inserted before lookup"))
}
