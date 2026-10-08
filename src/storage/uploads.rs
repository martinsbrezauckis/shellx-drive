mod admission;
mod advancement;
mod completion;
mod completion_outcome;
#[cfg(test)]
mod completion_tests;
mod lifecycle;
mod sessions;

pub(super) const TERMINAL_UPLOAD_RETENTION_PER_WORKSPACE: i64 = 1_000;

use chrono::Utc;
use rusqlite::{params, OptionalExtension, Row, TransactionBehavior};
use uuid::Uuid;

use self::admission::{
    complete_upload_session_in_tx, enforce_upload_completion_quota,
    ensure_upload_finalizer_permission, insert_upload_receipt_in_tx,
};
use super::{
    background_jobs, bounded_files::ensure_workspace_node_capacity,
    derived_names::derive_conflict_file_name, file_destination::available_copy_name_in_tx,
    human_item_grants::access::ensure_item_destination_authorized_in_tx, Storage,
};
use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind, Receipt, StaleRevisionResponse, UploadSession},
};

#[derive(Debug, Clone, Copy)]
pub struct UploadAdmissionPolicy {
    pub max_session_bytes: i64,
    pub max_actor_sessions: i64,
    pub max_workspace_sessions: i64,
    pub max_global_sessions: i64,
    pub max_actor_reserved_bytes: i64,
    pub max_workspace_reserved_bytes: i64,
    pub max_global_reserved_bytes: i64,
}

pub struct UploadSessionCreate<'a> {
    pub workspace_id: &'a str,
    pub actor_email: &'a str,
    pub parent_id: Option<String>,
    pub name: &'a str,
    pub total_size: Option<i64>,
    pub path: Option<String>,
    pub duplicate_policy: &'a str,
}

pub(crate) struct NewUploadCompletion<'a> {
    pub upload_id: &'a str,
    pub actor: &'a Actor,
    pub source_credential: &'a DriveCredential,
    pub received_bytes: i64,
    pub parent_id: Option<String>,
    pub name: String,
    pub content_hash: &'a str,
}

/// One durable terminal outcome for a resumable upload. A replacement whose
/// base is stale completes as a conflict file instead of mutating the current
/// target revision.
pub struct CompletedUpload {
    pub session: UploadSession,
    pub file: DriveFile,
    pub receipt: Receipt,
    pub conflict: Option<StaleRevisionResponse>,
}

impl Default for UploadAdmissionPolicy {
    fn default() -> Self {
        const GIB: i64 = 1024 * 1024 * 1024;
        Self {
            max_session_bytes: 2 * GIB,
            max_actor_sessions: 8,
            max_workspace_sessions: 32,
            max_global_sessions: 256,
            max_actor_reserved_bytes: 8 * GIB,
            max_workspace_reserved_bytes: 32 * GIB,
            max_global_reserved_bytes: 64 * GIB,
        }
    }
}

impl Storage {
    pub fn get_upload_session(&self, upload_id: &str) -> ApiResult<Option<UploadSession>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT id, workspace_id, actor_email, parent_id, name, total_size, received_bytes, completed, canceled, file_id, created_at, updated_at, canceled_at, path,
                        target_file_id, base_revision, completion_receipt_id,
                        completion_current_revision, duplicate_policy
                 FROM upload_sessions WHERE id = ?1",
                params![upload_id],
                row_to_upload_session,
            )
            .optional()?)
    }

    pub fn complete_upload_session(
        &self,
        upload_id: &str,
        file_id: &str,
        received_bytes: i64,
    ) -> ApiResult<(UploadSession, Receipt)> {
        let updated_at = Utc::now().to_rfc3339();
        let receipt = Receipt {
            id: Uuid::now_v7().to_string(),
            kind: "upload.complete".to_string(),
            actor: "system".to_string(),
            target_id: Some(file_id.to_string()),
            created_at: updated_at.clone(),
        };
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if tx.execute(
                "UPDATE upload_sessions
                 SET received_bytes = ?1, completed = 1, file_id = ?2, updated_at = ?3,
                     completion_receipt_id = ?4, completion_current_revision = NULL
                 WHERE id = ?5 AND completed = 0 AND canceled = 0",
                params![received_bytes, file_id, &updated_at, &receipt.id, upload_id],
            )? != 1
            {
                return Err(ApiError::Conflict);
            }
            insert_upload_receipt_in_tx(&tx, &receipt)?;
            tx.commit()?;
        }
        let session = self
            .get_upload_session(upload_id)?
            .ok_or(ApiError::NotFound)?;
        Ok((session, receipt))
    }

    /// Finalize a replacement in the one SQLite transaction that also records
    /// its revision and marks the session complete. A stale base creates a
    /// conflict file in that same transaction, preserving both revisions.
    pub fn complete_replacement_upload_session(
        &self,
        upload_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
        received_bytes: i64,
        content_hash: &str,
    ) -> ApiResult<CompletedUpload> {
        let content_bytes = received_bytes;
        let outcome = {
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
            if session.completed || session.canceled {
                return Err(ApiError::Conflict);
            }
            if !actor.is_admin && session.actor_email != actor.email {
                return Err(ApiError::NotFound);
            }
            let target_file_id = session.target_file_id.as_deref().ok_or_else(|| {
                ApiError::Validation("upload is not a replacement session".to_string())
            })?;
            let base_revision = session.base_revision.ok_or_else(|| {
                ApiError::Validation("replacement upload is missing base_revision".to_string())
            })?;
            let total_size = session.total_size.ok_or_else(|| {
                ApiError::Validation("upload session is missing total_size".to_string())
            })?;
            if received_bytes != total_size {
                return Err(ApiError::Validation(
                    "finished upload size does not match total_size".to_string(),
                ));
            }
            let target = tx
                .query_row(
                    "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                            content_hash, created_at, updated_at, content_bytes, cover_hash
                     FROM files WHERE id = ?1",
                    params![target_file_id],
                    super::row_to_file,
                )
                .optional()?
                .ok_or(ApiError::Conflict)?;
            if target.workspace_id != session.workspace_id
                || !matches!(target.kind, FileKind::File)
                || target.trashed
            {
                return Err(ApiError::Conflict);
            }
            ensure_upload_finalizer_permission(&tx, &session, actor, source_credential)?;
            // Re-read the workspace inside the mutation transaction so a
            // removed workspace/storage mode cannot be finalized through an
            // older session snapshot.
            let _: String = tx
                .query_row(
                    "SELECT storage_mode FROM workspaces WHERE id = ?1",
                    params![&target.workspace_id],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            let quota_bytes = tx
                .query_row(
                    "SELECT quota_bytes FROM workspace_policies WHERE workspace_id = ?1",
                    params![&target.workspace_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten();
            let now = Utc::now().to_rfc3339();

            if target.revision == base_revision {
                if let Some(quota_bytes) = quota_bytes {
                    enforce_upload_completion_quota(
                        &tx,
                        quota_bytes,
                        &target.workspace_id,
                        Some(&target.id),
                        content_bytes,
                        upload_id,
                    )?;
                }
                let mut file = target.clone();
                file.revision += 1;
                file.content_hash = Some(content_hash.to_string());
                file.size_bytes = Some(content_bytes);
                file.updated_at = now.clone();
                if tx.execute(
                    "UPDATE files
                     SET revision = ?1, content_hash = ?2, content_bytes = ?3, updated_at = ?4
                     WHERE id = ?5 AND revision = ?6 AND trashed = 0",
                    params![
                        file.revision,
                        &file.content_hash,
                        content_bytes,
                        &file.updated_at,
                        &file.id,
                        base_revision,
                    ],
                )? != 1
                {
                    return Err(ApiError::Conflict);
                }
                tx.execute(
                    "INSERT INTO file_revisions
                        (id, file_id, revision, content_hash, content_bytes, created_at, conflict_of_revision)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                    params![
                        Uuid::now_v7().to_string(),
                        &file.id,
                        file.revision,
                        &file.content_hash,
                        content_bytes,
                        &file.updated_at,
                    ],
                )?;
                super::refresh_file_search_index_locked(&tx, &file.id)?;
                let receipt = Receipt {
                    id: Uuid::now_v7().to_string(),
                    kind: "upload.complete".to_string(),
                    actor: actor.email.clone(),
                    target_id: Some(file.id.clone()),
                    created_at: now.clone(),
                };
                let mut session = session;
                session.received_bytes = received_bytes;
                session.completed = true;
                session.file_id = Some(file.id.clone());
                session.updated_at = now;
                session.completion_receipt_id = Some(receipt.id.clone());
                session.completion_current_revision = None;
                complete_upload_session_in_tx(&tx, &session, &receipt)?;
                let _ = background_jobs::enqueue_file_background_jobs_in_tx(&tx, &file)?;
                tx.commit()?;
                CompletedUpload {
                    session,
                    file,
                    receipt,
                    conflict: None,
                }
            } else {
                ensure_item_destination_authorized_in_tx(
                    &tx,
                    &target.workspace_id,
                    target.parent_id.as_deref(),
                    actor,
                    source_credential,
                )?;
                if let Some(quota_bytes) = quota_bytes {
                    enforce_upload_completion_quota(
                        &tx,
                        quota_bytes,
                        &target.workspace_id,
                        None,
                        content_bytes,
                        upload_id,
                    )?;
                }
                let conflict_name = available_copy_name_in_tx(
                    &tx,
                    &target.workspace_id,
                    target.parent_id.as_deref(),
                    &derive_conflict_file_name(&target.name, &now)?,
                )?;
                let conflict_file = DriveFile {
                    id: Uuid::now_v7().to_string(),
                    workspace_id: target.workspace_id.clone(),
                    parent_id: target.parent_id.clone(),
                    name: conflict_name,
                    kind: FileKind::File,
                    revision: 1,
                    trashed: false,
                    starred: false,
                    content_hash: Some(content_hash.to_string()),
                    created_at: now.clone(),
                    updated_at: now.clone(),
                    size_bytes: Some(content_bytes),
                    folder_size_bytes: None,
                    has_cover: false,
                };
                ensure_workspace_node_capacity(&tx, &target.workspace_id, 1)?;
                tx.execute(
                    "INSERT INTO files (id, workspace_id, parent_id, name, kind, revision, trashed, starred, content_hash, content_bytes, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 1, 0, 0, ?6, ?7, ?8, ?8)",
                    params![
                        &conflict_file.id,
                        &conflict_file.workspace_id,
                        &conflict_file.parent_id,
                        &conflict_file.name,
                        conflict_file.kind.as_db_str(),
                        &conflict_file.content_hash,
                        content_bytes,
                        &conflict_file.created_at,
                    ],
                )?;
                tx.execute(
                    "INSERT INTO file_revisions
                        (id, file_id, revision, content_hash, content_bytes, created_at,
                         conflict_of_revision, conflict_of_file_id)
                     VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        Uuid::now_v7().to_string(),
                        &conflict_file.id,
                        &conflict_file.content_hash,
                        content_bytes,
                        &conflict_file.created_at,
                        base_revision,
                        &target.id,
                    ],
                )?;
                super::refresh_file_search_index_locked(&tx, &conflict_file.id)?;
                let receipt = Receipt {
                    id: Uuid::now_v7().to_string(),
                    kind: "file.conflict".to_string(),
                    actor: actor.email.clone(),
                    target_id: Some(conflict_file.id.clone()),
                    created_at: now.clone(),
                };
                let conflict = StaleRevisionResponse {
                    error: "stale_revision",
                    file_id: target.id.clone(),
                    attempted_base_revision: base_revision,
                    current_revision: target.revision,
                    conflict_file_id: conflict_file.id.clone(),
                    receipt: receipt.clone(),
                };
                let mut session = session;
                session.received_bytes = received_bytes;
                session.completed = true;
                session.file_id = Some(conflict_file.id.clone());
                session.updated_at = now;
                session.completion_receipt_id = Some(receipt.id.clone());
                session.completion_current_revision = Some(target.revision);
                complete_upload_session_in_tx(&tx, &session, &receipt)?;
                let _ = background_jobs::enqueue_file_background_jobs_in_tx(&tx, &conflict_file)?;
                tx.commit()?;
                CompletedUpload {
                    session,
                    file: conflict_file,
                    receipt,
                    conflict: Some(conflict),
                }
            }
        };
        Ok(outcome)
    }
}

pub(super) fn row_to_upload_session(row: &Row<'_>) -> rusqlite::Result<UploadSession> {
    let id: String = row.get(0)?;
    let completed: i64 = row.get(7)?;
    let canceled: i64 = row.get(8)?;
    Ok(UploadSession {
        upload_url: format!("/uploads/resumable/{id}"),
        id,
        workspace_id: row.get(1)?,
        actor_email: row.get(2)?,
        parent_id: row.get(3)?,
        name: row.get(4)?,
        total_size: row.get(5)?,
        received_bytes: row.get(6)?,
        completed: completed != 0,
        canceled: canceled != 0,
        file_id: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        canceled_at: row.get(12)?,
        path: row.get(13)?,
        target_file_id: row.get(14)?,
        base_revision: row.get(15)?,
        completion_receipt_id: row.get(16)?,
        completion_current_revision: row.get(17)?,
        duplicate_policy: row.get(18)?,
    })
}
