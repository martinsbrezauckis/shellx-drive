use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{FileKind, UploadSession},
};

use super::{admission::enforce_upload_admission, UploadAdmissionPolicy, UploadSessionCreate};
use crate::storage::{validate_file_name, Storage};

impl Storage {
    pub fn create_upload_session(
        &self,
        request: UploadSessionCreate<'_>,
        policy: UploadAdmissionPolicy,
    ) -> ApiResult<UploadSession> {
        self.create_upload_session_inner(request, policy, None)
    }

    pub(crate) fn create_upload_session_authorized(
        &self,
        request: UploadSessionCreate<'_>,
        policy: UploadAdmissionPolicy,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<UploadSession> {
        self.create_upload_session_inner(request, policy, Some((actor, source_credential)))
    }

    fn create_upload_session_inner(
        &self,
        request: UploadSessionCreate<'_>,
        policy: UploadAdmissionPolicy,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<UploadSession> {
        self.workspace_storage_mode(request.workspace_id)?;
        let declared_size = request.total_size.ok_or_else(|| {
            ApiError::Validation("total_size is required for resumable uploads".to_string())
        })?;
        if declared_size < 0 {
            return Err(ApiError::Validation(
                "total_size must not be negative".to_string(),
            ));
        }
        if declared_size > policy.max_session_bytes {
            return Err(ApiError::PayloadTooLarge(format!(
                "resumable uploads must not exceed {} bytes",
                policy.max_session_bytes
            )));
        }
        if let Some(parent_id) = request.parent_id.as_ref() {
            self.validate_upload_parent(request.workspace_id, parent_id)?;
        }
        let name = validate_file_name(request.name)?;
        let now = Utc::now().to_rfc3339();
        let id = Uuid::now_v7().to_string();
        let session = UploadSession {
            upload_url: format!("/uploads/resumable/{id}"),
            id,
            workspace_id: request.workspace_id.to_string(),
            actor_email: request.actor_email.to_string(),
            parent_id: request.parent_id.clone(),
            name,
            total_size: request.total_size,
            received_bytes: 0,
            completed: false,
            canceled: false,
            file_id: None,
            created_at: now.clone(),
            updated_at: now,
            canceled_at: None,
            path: request.path,
            duplicate_policy: request.duplicate_policy.to_string(),
            target_file_id: None,
            base_revision: None,
            completion_receipt_id: None,
            completion_current_revision: None,
        };
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if let Some((actor, source_credential)) = authorization_context {
                crate::storage::human_item_grants::access::ensure_item_destination_authorized_in_tx(
                    &tx,
                    request.workspace_id,
                    request.parent_id.as_deref(),
                    actor,
                    source_credential,
                )?;
            }
            enforce_upload_admission(
                &tx,
                request.workspace_id,
                request.actor_email,
                declared_size,
                declared_size.max(1),
                policy,
            )?;
            tx.execute(
                "INSERT INTO upload_sessions (
                    id, workspace_id, actor_email, parent_id, name, total_size,
                    received_bytes, completed, file_id, created_at, updated_at, path,
                    target_file_id, base_revision, completion_receipt_id,
                    completion_current_revision, quota_reservation_bytes, duplicate_policy
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, NULL, ?7, ?7, ?8,
                           NULL, NULL, NULL, NULL, ?9, ?10)",
                params![
                    &session.id,
                    &session.workspace_id,
                    &session.actor_email,
                    &session.parent_id,
                    &session.name,
                    session.total_size,
                    &session.created_at,
                    &session.path,
                    declared_size.max(1),
                    &session.duplicate_policy,
                ],
            )?;
            tx.commit()?;
        }
        self.insert_receipt("upload.start", "system", Some(&session.id))?;
        Ok(session)
    }

    /// Create a session that can replace exactly one live regular file. The
    /// target row is read inside the admission transaction and supplies every
    /// identity field persisted on the session; caller-supplied workspace,
    /// parent, and name never participate in replacement routing.
    pub fn create_replacement_upload_session(
        &self,
        target_file_id: &str,
        base_revision: i64,
        actor_email: &str,
        total_size: i64,
        policy: UploadAdmissionPolicy,
    ) -> ApiResult<UploadSession> {
        self.create_replacement_upload_session_inner(
            target_file_id,
            base_revision,
            actor_email,
            total_size,
            policy,
            None,
        )
    }

    pub(crate) fn create_replacement_upload_session_authorized(
        &self,
        target_file_id: &str,
        base_revision: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
        total_size: i64,
        policy: UploadAdmissionPolicy,
    ) -> ApiResult<UploadSession> {
        self.create_replacement_upload_session_inner(
            target_file_id,
            base_revision,
            &actor.email,
            total_size,
            policy,
            Some((actor, source_credential)),
        )
    }

    fn create_replacement_upload_session_inner(
        &self,
        target_file_id: &str,
        base_revision: i64,
        actor_email: &str,
        total_size: i64,
        policy: UploadAdmissionPolicy,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<UploadSession> {
        if total_size < 0 {
            return Err(ApiError::Validation(
                "total_size must not be negative".to_string(),
            ));
        }
        if total_size > policy.max_session_bytes {
            return Err(ApiError::PayloadTooLarge(format!(
                "resumable uploads must not exceed {} bytes",
                policy.max_session_bytes
            )));
        }

        let id = Uuid::now_v7().to_string();
        let now = Utc::now().to_rfc3339();
        let session = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let target = tx
                .query_row(
                    "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                            content_hash, created_at, updated_at, content_bytes, cover_hash
                     FROM files WHERE id = ?1",
                    params![target_file_id],
                    crate::storage::row_to_file,
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if !matches!(target.kind, FileKind::File) || target.trashed {
                return Err(ApiError::Validation(
                    "resumable replacements require one live regular file".to_string(),
                ));
            }
            if let Some((actor, source_credential)) = authorization_context {
                crate::storage::human_item_grants::access::ensure_item_authorized_in_tx(
                    &tx,
                    target_file_id,
                    actor,
                    source_credential,
                    WorkspacePermission::Write,
                )?;
            }
            // The old current body becomes retained history on replacement, so
            // the complete new body is additional logical storage.
            let quota_reservation = total_size.max(1);
            enforce_upload_admission(
                &tx,
                &target.workspace_id,
                actor_email,
                total_size,
                quota_reservation,
                policy,
            )?;
            let session = UploadSession {
                upload_url: format!("/uploads/resumable/{id}"),
                id: id.clone(),
                workspace_id: target.workspace_id,
                actor_email: actor_email.to_string(),
                parent_id: target.parent_id,
                name: target.name,
                total_size: Some(total_size),
                received_bytes: 0,
                completed: false,
                canceled: false,
                file_id: None,
                created_at: now.clone(),
                updated_at: now.clone(),
                canceled_at: None,
                path: None,
                duplicate_policy: "replace".to_string(),
                target_file_id: Some(target_file_id.to_string()),
                base_revision: Some(base_revision),
                completion_receipt_id: None,
                completion_current_revision: None,
            };
            tx.execute(
                "INSERT INTO upload_sessions (
                    id, workspace_id, actor_email, parent_id, name, total_size,
                    received_bytes, completed, file_id, created_at, updated_at, path,
                    target_file_id, base_revision, completion_receipt_id,
                    completion_current_revision, quota_reservation_bytes, duplicate_policy
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, NULL, ?7, ?7, NULL,
                           ?8, ?9, NULL, NULL, ?10, ?11)",
                params![
                    &session.id,
                    &session.workspace_id,
                    &session.actor_email,
                    &session.parent_id,
                    &session.name,
                    session.total_size,
                    &session.created_at,
                    &session.target_file_id,
                    session.base_revision,
                    quota_reservation,
                    &session.duplicate_policy,
                ],
            )?;
            tx.commit()?;
            session
        };
        self.insert_receipt("upload.start", actor_email, Some(&session.id))?;
        Ok(session)
    }
}
