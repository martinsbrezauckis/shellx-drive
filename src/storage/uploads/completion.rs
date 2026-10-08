use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use super::{
    admission::{
        complete_upload_session_in_tx, enforce_upload_completion_quota,
        ensure_upload_finalizer_permission,
    },
    row_to_upload_session, CompletedUpload, NewUploadCompletion,
};
use crate::{
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind, Receipt},
    storage::{
        background_jobs, bounded_files::ensure_workspace_node_capacity,
        file_destination::available_copy_name_in_tx,
        human_item_grants::access::ensure_item_destination_authorized_in_tx, insert_receipt_rows,
        new_receipt, refresh_file_search_index_locked, validate_file_name,
        validate_parent_chain_in_tx, Storage,
    },
};

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_NEW_UPLOAD_COMPLETION_BEFORE_COMMIT: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(super) fn fail_next_new_upload_completion_before_commit() {
    FAIL_NEXT_NEW_UPLOAD_COMPLETION_BEFORE_COMMIT.with(|flag| flag.set(true));
}

fn maybe_fail_new_upload_completion_before_commit() -> ApiResult<()> {
    #[cfg(test)]
    if FAIL_NEXT_NEW_UPLOAD_COMPLETION_BEFORE_COMMIT.with(|flag| flag.replace(false)) {
        return Err(ApiError::Maintenance(
            "injected new upload finalization interruption".to_string(),
        ));
    }
    Ok(())
}

impl Storage {
    /// Atomically materialize a new-file upload, its durable terminal outcome,
    /// receipts, and required derived-work admission. The blob has already been
    /// published under the caller's publication guard; SQLite is the single
    /// commit point for all references to it.
    pub(crate) fn complete_new_upload_session(
        &self,
        input: NewUploadCompletion<'_>,
    ) -> ApiResult<CompletedUpload> {
        let NewUploadCompletion {
            upload_id,
            actor,
            source_credential,
            received_bytes,
            parent_id,
            name,
            content_hash,
        } = input;
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
            if session.completed || session.canceled || session.target_file_id.is_some() {
                return Err(ApiError::Conflict);
            }
            if !actor.is_admin && session.actor_email != actor.email {
                return Err(ApiError::NotFound);
            }
            let total_size = session.total_size.ok_or_else(|| {
                ApiError::Validation("upload session is missing total_size".to_string())
            })?;
            if received_bytes != total_size {
                return Err(ApiError::Validation(
                    "finished upload size does not match total_size".to_string(),
                ));
            }
            ensure_upload_finalizer_permission(&tx, &session, actor, source_credential)?;
            let _: String = tx
                .query_row(
                    "SELECT storage_mode FROM workspaces WHERE id = ?1",
                    params![&session.workspace_id],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if let Some(parent_id) = parent_id.as_deref() {
                validate_parent_chain_in_tx(&tx, &session.workspace_id, parent_id, None)?;
            }
            ensure_item_destination_authorized_in_tx(
                &tx,
                &session.workspace_id,
                parent_id.as_deref(),
                actor,
                source_credential,
            )?;
            let quota_bytes = tx
                .query_row(
                    "SELECT quota_bytes FROM workspace_policies WHERE workspace_id = ?1",
                    params![&session.workspace_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten();
            if let Some(quota_bytes) = quota_bytes {
                enforce_upload_completion_quota(
                    &tx,
                    quota_bytes,
                    &session.workspace_id,
                    None,
                    received_bytes,
                    upload_id,
                )?;
            }
            ensure_workspace_node_capacity(&tx, &session.workspace_id, 1)?;

            let now = Utc::now().to_rfc3339();
            let requested_name = validate_file_name(&name)?;
            let available_name = available_copy_name_in_tx(
                &tx,
                &session.workspace_id,
                parent_id.as_deref(),
                &requested_name,
            )?;
            let name = match session.duplicate_policy.as_str() {
                "keep_both" => available_name,
                "cancel" if available_name == requested_name => available_name,
                "cancel" => return Err(ApiError::Conflict),
                _ => {
                    return Err(ApiError::Maintenance(
                        "new upload session has an unsupported duplicate policy".to_string(),
                    ));
                }
            };
            let file = DriveFile {
                id: Uuid::now_v7().to_string(),
                workspace_id: session.workspace_id.clone(),
                parent_id,
                name,
                kind: FileKind::File,
                revision: 1,
                trashed: false,
                starred: false,
                content_hash: Some(content_hash.to_string()),
                created_at: now.clone(),
                updated_at: now.clone(),
                size_bytes: Some(received_bytes),
                folder_size_bytes: None,
                has_cover: false,
            };
            tx.execute(
                "INSERT INTO files (id, workspace_id, parent_id, name, kind, revision, trashed, starred, content_hash, content_bytes, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, 0, 0, ?6, ?7, ?8, ?8)",
                params![
                    &file.id,
                    &file.workspace_id,
                    &file.parent_id,
                    &file.name,
                    file.kind.as_db_str(),
                    &file.content_hash,
                    received_bytes,
                    &file.created_at,
                ],
            )?;
            tx.execute(
                "INSERT INTO file_revisions (id, file_id, revision, content_hash, content_bytes, created_at, conflict_of_revision)
                 VALUES (?1, ?2, 1, ?3, ?4, ?5, NULL)",
                params![
                    Uuid::now_v7().to_string(),
                    &file.id,
                    &file.content_hash,
                    received_bytes,
                    &file.created_at,
                ],
            )?;
            refresh_file_search_index_locked(&tx, &file.id)?;
            let file_receipt = new_receipt("file.create", &actor.email, Some(&file.id));
            insert_receipt_rows(&tx, &file_receipt)?;
            let receipt = Receipt {
                id: Uuid::now_v7().to_string(),
                kind: "upload.complete".to_string(),
                actor: "system".to_string(),
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
            maybe_fail_new_upload_completion_before_commit()?;
            tx.commit()?;
            CompletedUpload {
                session,
                file,
                receipt,
                conflict: None,
            }
        };
        Ok(outcome)
    }
}
