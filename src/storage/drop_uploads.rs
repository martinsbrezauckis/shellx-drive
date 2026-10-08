mod inbox;
mod stale_cleanup;

use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension, Row};
use uuid::Uuid;

use crate::{
    auth::{constant_time_str_eq, random_secret_token, token_hash},
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind, Receipt},
};

use super::quota_reservations::{enforce_workspace_quota_with_reservations, ReservationExclusions};
use super::{
    auth_attempt_key, background_jobs, bounded_files::ensure_workspace_node_capacity,
    file_destination::available_copy_name_in_tx, insert_receipt_rows, new_receipt,
    normalize_relative_upload_path, refresh_file_search_index_locked, row_to_file,
    validate_file_name, validate_non_negative_i64, Storage,
};

pub const MAX_COMPLETED_FILES_PER_DROP: i64 = 10_000;
const MAX_TERMINAL_UPLOAD_SESSIONS_PER_DROP: i64 = 100;

#[derive(Debug, Clone)]
pub struct DropUploadRecord {
    pub id: String,
    pub drop_id: String,
    pub workspace_id: String,
    /// Possession binding for the browser/native client that created the
    /// session. This is deliberately distinct from transport admission.
    pub client_fingerprint: String,
    /// Server-derived request partition used for durable resource admission.
    pub transport_fingerprint: String,
    pub name: String,
    pub path: Option<String>,
    pub content_type: Option<String>,
    pub total_size: i64,
    pub received_bytes: i64,
    pub chunk_count: i64,
    pub status: String,
    pub file_id: Option<String>,
    pub last_error_code: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
    pub canceled_at: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DropUploadTotals {
    pub total: i64,
    pub active: i64,
    pub completed: i64,
    pub canceled: i64,
    pub failed: i64,
    pub active_received_bytes: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct DropUploadAdmissionPolicy {
    pub max_session_bytes: i64,
    pub max_client_sessions: i64,
    pub max_drop_sessions: i64,
    pub max_workspace_sessions: i64,
    pub max_global_sessions: i64,
    pub max_client_reserved_bytes: i64,
    pub max_drop_bytes: i64,
    pub max_workspace_bytes: i64,
    pub max_global_bytes: i64,
}

pub struct DropUploadSessionCreate<'a> {
    pub drop_id: &'a str,
    pub workspace_id: &'a str,
    /// Proof-of-possession binding for later session ownership checks.
    pub client_fingerprint: &'a str,
    /// Server-derived request fingerprint for resource admission only.
    pub transport_fingerprint: &'a str,
    pub expected_authorization_fingerprint: &'a str,
    pub name: &'a str,
    pub path: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub total_size: i64,
    pub policy: DropUploadAdmissionPolicy,
}

impl Default for DropUploadAdmissionPolicy {
    fn default() -> Self {
        const GIB: i64 = 1024 * 1024 * 1024;
        Self {
            max_session_bytes: 2 * GIB,
            max_client_sessions: 4,
            max_drop_sessions: 16,
            max_workspace_sessions: 64,
            max_global_sessions: 128,
            max_client_reserved_bytes: 2 * GIB,
            max_drop_bytes: 8 * GIB,
            max_workspace_bytes: 16 * GIB,
            max_global_bytes: 32 * GIB,
        }
    }
}

impl Storage {
    /// Consume a public request budget partitioned by capability and the
    /// server-derived client fingerprint. This is separate from password
    /// lockouts: a client with the correct password is still bounded.
    pub fn consume_partitioned_public_rate_limit(
        &self,
        resource_id: &str,
        scope: &str,
        client_fingerprint: &str,
        limit: i64,
        window_seconds: i64,
    ) -> ApiResult<()> {
        let limit = limit.max(1);
        let window_seconds = window_seconds.max(1);
        let key = auth_attempt_key(Some(resource_id), scope, Some(client_fingerprint));
        if self.public_rate_limit_denials.denies(&key) {
            return Err(ApiError::TooManyRequests);
        }
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let window_start = now - Duration::seconds(window_seconds);
        let conn = self.conn.lock().unwrap();
        let existing = conn
            .query_row(
                "SELECT failures, updated_at FROM auth_attempts WHERE key = ?1",
                params![&key],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let active = existing.and_then(|(attempts, updated_at)| {
            DateTime::parse_from_rfc3339(&updated_at)
                .ok()
                .filter(|updated_at| updated_at.with_timezone(&Utc) > window_start)
                .map(|updated_at| (attempts, updated_at.with_timezone(&Utc)))
        });
        if let Some((attempts, started_at)) = active.as_ref() {
            if *attempts >= limit {
                let remaining = (*started_at + Duration::seconds(window_seconds) - now)
                    .to_std()
                    .unwrap_or_default();
                drop(conn);
                self.public_rate_limit_denials.deny_for(&key, remaining);
                return Err(ApiError::TooManyRequests);
            }
        }
        let previous = active.map(|(attempts, _)| attempts).unwrap_or(0);
        let attempts = previous.saturating_add(1);
        let locked_until =
            (attempts >= limit).then(|| (now + Duration::seconds(window_seconds)).to_rfc3339());
        super::prune_auth_attempts_locked(&conn, &now_text)?;
        conn.execute(
            "INSERT INTO auth_attempts (
                key, actor_email, client_fingerprint, scope, failures, locked_until, updated_at
             ) VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(key) DO UPDATE SET
                actor_email = NULL,
                client_fingerprint = excluded.client_fingerprint,
                scope = excluded.scope,
                failures = excluded.failures,
                locked_until = excluded.locked_until,
                updated_at = excluded.updated_at",
            params![
                &key,
                client_fingerprint,
                scope,
                attempts,
                locked_until,
                &now_text
            ],
        )?;
        super::enforce_auth_attempt_row_cap_locked(&conn)?;
        Ok(())
    }

    pub fn create_drop_upload_session(
        &self,
        request: DropUploadSessionCreate<'_>,
    ) -> ApiResult<(DropUploadRecord, Receipt)> {
        self.workspace_storage_mode(request.workspace_id)?;
        let name = validate_file_name(request.name)?;
        let path = request
            .path
            .map(normalize_relative_upload_path)
            .transpose()?
            .filter(|path| !path.is_empty());
        if let Some(path) = path.as_deref() {
            let leaf = path.rsplit('/').next().unwrap_or_default();
            if leaf != name {
                return Err(ApiError::Validation(
                    "path leaf must match the declared file name".to_string(),
                ));
            }
        }
        let content_type = request
            .content_type
            .map(validate_declared_content_type)
            .transpose()?;
        let total_size = validate_non_negative_i64(request.total_size, "total_size")?;
        if total_size > request.policy.max_session_bytes {
            return Err(ApiError::PayloadTooLarge(format!(
                "Drop uploads must not exceed {} bytes",
                request.policy.max_session_bytes
            )));
        }
        let now = Utc::now().to_rfc3339();
        let id = random_secret_token();
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            prune_terminal_drop_upload_sessions_in_tx(&tx, request.drop_id)?;
            let (active_password_hash, completed_uploads) = tx
                .query_row(
                    "SELECT password_hash, upload_count FROM drops
                 WHERE id = ?1 AND workspace_id = ?2 AND publication_pending = 0
                   AND revoked = 0 AND expires_at > ?3",
                    params![request.drop_id, request.workspace_id, &now],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if completed_uploads >= MAX_COMPLETED_FILES_PER_DROP {
                return Err(ApiError::TooManyRequests);
            }
            let current_fingerprint =
                token_hash(&format!("drop-authorization-v1\0{active_password_hash}"));
            if !constant_time_str_eq(
                request.expected_authorization_fingerprint,
                &current_fingerprint,
            ) {
                return Err(ApiError::Unauthenticated);
            }
            inbox::inbox_for_drop_in_tx(&tx, request.drop_id, request.workspace_id)?;
            ensure_workspace_node_capacity(&tx, request.workspace_id, 1)?;
            enforce_drop_upload_admission(
                &tx,
                request.drop_id,
                request.workspace_id,
                request.transport_fingerprint,
                total_size,
                request.policy,
            )?;
            enforce_workspace_quota_with_reservations(
                &tx,
                request.workspace_id,
                total_size.max(1),
                ReservationExclusions::default(),
            )?;
            tx.execute(
                "INSERT INTO drop_upload_sessions (
                    id, drop_id, workspace_id, client_fingerprint, transport_fingerprint, name, path,
                    content_type, total_size, received_bytes, chunk_count,
                    status, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, 0, 'active', ?10, ?10)",
                params![
                    &id,
                    request.drop_id,
                    request.workspace_id,
                    request.client_fingerprint,
                    request.transport_fingerprint,
                    &name,
                    &path,
                    &content_type,
                    total_size,
                    &now
                ],
            )?;
            tx.commit()?;
        }
        let session = self
            .get_drop_upload_session(&id)?
            .ok_or(ApiError::NotFound)?;
        let receipt = self.insert_receipt("drop.upload.start", "public", Some(request.drop_id))?;
        Ok((session, receipt))
    }

    pub fn get_drop_upload_session(&self, session_id: &str) -> ApiResult<Option<DropUploadRecord>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT id, drop_id, workspace_id, client_fingerprint, transport_fingerprint, name, path,
                        content_type, total_size, received_bytes, chunk_count,
                        status, file_id, last_error_code, created_at, updated_at,
                        completed_at, canceled_at
                 FROM drop_upload_sessions WHERE id = ?1",
                params![session_id],
                row_to_drop_upload_record,
            )
            .optional()?)
    }

    pub fn list_drop_upload_sessions(&self, drop_id: &str) -> ApiResult<Vec<DropUploadRecord>> {
        self.get_drop(drop_id)?.ok_or(ApiError::NotFound)?;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, drop_id, workspace_id, client_fingerprint, transport_fingerprint, name, path,
                    content_type, total_size, received_bytes, chunk_count,
                    status, file_id, last_error_code, created_at, updated_at,
                    completed_at, canceled_at
             FROM drop_upload_sessions
             WHERE drop_id = ?1
             ORDER BY created_at DESC, id DESC
             LIMIT 250",
        )?;
        let rows = stmt.query_map(params![drop_id], row_to_drop_upload_record)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(crate) fn drop_upload_totals(&self, drop_id: &str) -> ApiResult<DropUploadTotals> {
        self.get_drop(drop_id)?.ok_or(ApiError::NotFound)?;
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status = 'canceled' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status = 'active' THEN received_bytes ELSE 0 END), 0)
             FROM drop_upload_sessions WHERE drop_id = ?1",
            params![drop_id],
            |row| {
                Ok(DropUploadTotals {
                    total: row.get(0)?,
                    active: row.get(1)?,
                    completed: row.get(2)?,
                    canceled: row.get(3)?,
                    failed: row.get(4)?,
                    active_received_bytes: row.get(5)?,
                })
            },
        )?)
    }

    pub fn update_drop_upload_received(
        &self,
        session_id: &str,
        expected_offset: i64,
        received_bytes: i64,
    ) -> ApiResult<DropUploadRecord> {
        let now = Utc::now().to_rfc3339();
        let changed = {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "UPDATE drop_upload_sessions
                 SET received_bytes = ?1, chunk_count = chunk_count + 1, updated_at = ?2
                 WHERE id = ?3 AND status = 'active' AND received_bytes = ?4
                   AND EXISTS (
                       SELECT 1 FROM drops
                       WHERE drops.id = drop_upload_sessions.drop_id
                         AND drops.publication_pending = 0
                         AND drops.revoked = 0
                         AND drops.expires_at > ?2
                   )",
                params![received_bytes, &now, session_id, expected_offset],
            )?
        };
        if changed != 1 {
            return Err(ApiError::Conflict);
        }
        self.get_drop_upload_session(session_id)?
            .ok_or(ApiError::NotFound)
    }

    pub fn finalize_drop_upload_file(
        &self,
        session_id: &str,
        content_hash: &str,
    ) -> ApiResult<(DropUploadRecord, DriveFile, Receipt)> {
        let now = Utc::now().to_rfc3339();
        let (_, file, receipt) = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let session = tx
                .query_row(
                    "SELECT s.id, s.drop_id, s.workspace_id, s.client_fingerprint,
                            s.transport_fingerprint, s.name, s.path, s.content_type, s.total_size, s.received_bytes,
                            s.chunk_count, s.status, s.file_id, s.last_error_code,
                            s.created_at, s.updated_at, s.completed_at, s.canceled_at
                     FROM drop_upload_sessions s
                     JOIN drops d ON d.id = s.drop_id
                     WHERE s.id = ?1
                       AND s.status = 'active'
                       AND s.received_bytes = s.total_size
                       AND d.workspace_id = s.workspace_id
                       AND d.publication_pending = 0
                       AND d.revoked = 0
                       AND d.expires_at > ?2
                       AND d.upload_count < ?3",
                    params![session_id, &now, MAX_COMPLETED_FILES_PER_DROP],
                    row_to_drop_upload_record,
                )
                .optional()?
                .ok_or(ApiError::Conflict)?;

            let (folder_names, leaf_name) = match session.path.as_deref() {
                Some(path) => {
                    let normalized = normalize_relative_upload_path(path)?;
                    let mut segments = normalized
                        .split('/')
                        .map(str::to_string)
                        .collect::<Vec<_>>();
                    let leaf = segments.pop().ok_or_else(|| {
                        ApiError::Validation("upload path must not be empty".to_string())
                    })?;
                    (segments, leaf)
                }
                None => (Vec::new(), validate_file_name(&session.name)?),
            };
            if leaf_name != session.name {
                return Err(ApiError::Validation(
                    "path leaf must match the declared file name".to_string(),
                ));
            }

            let mut current_parent = Some(inbox::inbox_for_drop_in_tx(
                &tx,
                &session.drop_id,
                &session.workspace_id,
            )?);
            for folder_name in folder_names {
                let existing = active_child_locked(
                    &tx,
                    &session.workspace_id,
                    current_parent.as_deref(),
                    &folder_name,
                )?;
                current_parent = match existing {
                    Some(folder) if matches!(folder.kind, FileKind::Folder) => Some(folder.id),
                    Some(_) | None => {
                        ensure_workspace_node_capacity(&tx, &session.workspace_id, 1)?;
                        let folder_name = available_copy_name_in_tx(
                            &tx,
                            &session.workspace_id,
                            current_parent.as_deref(),
                            &folder_name,
                        )?;
                        let folder = DriveFile {
                            id: Uuid::now_v7().to_string(),
                            workspace_id: session.workspace_id.clone(),
                            parent_id: current_parent.clone(),
                            name: folder_name,
                            kind: FileKind::Folder,
                            revision: 1,
                            trashed: false,
                            starred: false,
                            content_hash: None,
                            created_at: now.clone(),
                            updated_at: now.clone(),
                            size_bytes: None,
                            folder_size_bytes: None,
                            has_cover: false,
                        };
                        tx.execute(
                            "INSERT INTO files (
                                id, workspace_id, parent_id, name, kind, revision, trashed,
                                starred, content_hash, content_bytes, created_at, updated_at
                             ) VALUES (?1, ?2, ?3, ?4, 'folder', 1, 0, 0, NULL, 0, ?5, ?5)",
                            params![
                                &folder.id,
                                &folder.workspace_id,
                                &folder.parent_id,
                                &folder.name,
                                &now
                            ],
                        )?;
                        tx.execute(
                            "INSERT INTO file_revisions (
                                id, file_id, revision, content_hash, content_bytes,
                                created_at, conflict_of_revision
                             ) VALUES (?1, ?2, 1, NULL, 0, ?3, NULL)",
                            params![Uuid::now_v7().to_string(), &folder.id, &now],
                        )?;
                        refresh_file_search_index_locked(&tx, &folder.id)?;
                        current_parent = Some(folder.id.clone());
                        current_parent
                    }
                };
            }

            // Charge new path folders, exclude this session's reservation, and
            // roll back folders and file together if finalization fails.
            enforce_workspace_quota_with_reservations(
                &tx,
                &session.workspace_id,
                session.total_size.max(1),
                ReservationExclusions {
                    upload_session_id: None,
                    drop_upload_session_id: Some(&session.id),
                },
            )?;

            ensure_workspace_node_capacity(&tx, &session.workspace_id, 1)?;
            let leaf_name = available_copy_name_in_tx(
                &tx,
                &session.workspace_id,
                current_parent.as_deref(),
                &leaf_name,
            )?;

            let file = DriveFile {
                id: Uuid::now_v7().to_string(),
                workspace_id: session.workspace_id.clone(),
                parent_id: current_parent,
                name: leaf_name,
                kind: FileKind::File,
                revision: 1,
                trashed: false,
                starred: false,
                content_hash: Some(content_hash.to_string()),
                created_at: now.clone(),
                updated_at: now.clone(),
                size_bytes: Some(session.total_size),
                folder_size_bytes: None,
                has_cover: false,
            };
            tx.execute(
                "INSERT INTO files (
                    id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                    content_hash, content_bytes, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, 'file', 1, 0, 0, ?5, ?6, ?7, ?7)",
                params![
                    &file.id,
                    &file.workspace_id,
                    &file.parent_id,
                    &file.name,
                    &file.content_hash,
                    session.total_size,
                    &now
                ],
            )?;
            tx.execute(
                "INSERT INTO file_revisions (
                    id, file_id, revision, content_hash, content_bytes,
                    created_at, conflict_of_revision
                 ) VALUES (?1, ?2, 1, ?3, ?4, ?5, NULL)",
                params![
                    Uuid::now_v7().to_string(),
                    &file.id,
                    &file.content_hash,
                    session.total_size,
                    &now
                ],
            )?;
            refresh_file_search_index_locked(&tx, &file.id)?;

            if tx.execute(
                "UPDATE drop_upload_sessions
                 SET status = 'completed', file_id = ?1, completed_at = ?2, updated_at = ?2
                 WHERE id = ?3 AND status = 'active'
                   AND EXISTS (
                       SELECT 1 FROM drops
                       WHERE drops.id = drop_upload_sessions.drop_id
                         AND drops.publication_pending = 0
                         AND drops.revoked = 0
                         AND drops.expires_at > ?2
                   )",
                params![&file.id, &now, session_id],
            )? != 1
            {
                return Err(ApiError::Conflict);
            }
            if tx.execute(
                "UPDATE drops
                 SET upload_count = upload_count + 1,
                     uploaded_bytes = uploaded_bytes + CASE
                         WHEN ?4 > 0 THEN ?4 ELSE 1 END,
                     last_uploaded_at = ?1
                 WHERE id = ?2 AND publication_pending = 0 AND revoked = 0 AND expires_at > ?1
                   AND upload_count < ?3",
                params![
                    &now,
                    &session.drop_id,
                    MAX_COMPLETED_FILES_PER_DROP,
                    session.total_size
                ],
            )? != 1
            {
                return Err(ApiError::Conflict);
            }
            let receipt = new_receipt("drop.upload", "public", Some(&session.drop_id));
            insert_receipt_rows(&tx, &receipt)?;
            let _ = background_jobs::enqueue_file_background_jobs_in_tx(&tx, &file)?;
            tx.commit()?;
            (session.drop_id, file, receipt)
        };
        let session = self
            .get_drop_upload_session(session_id)?
            .ok_or(ApiError::NotFound)?;
        Ok((session, file, receipt))
    }

    pub fn cancel_drop_upload_session(
        &self,
        session_id: &str,
    ) -> ApiResult<(DropUploadRecord, Receipt)> {
        let now = Utc::now().to_rfc3339();
        let session = self
            .get_drop_upload_session(session_id)?
            .ok_or(ApiError::NotFound)?;
        let changed = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let changed = tx.execute(
                "UPDATE drop_upload_sessions
                 SET status = 'canceled', canceled_at = ?1, updated_at = ?1
                 WHERE id = ?2 AND status = 'active'",
                params![&now, session_id],
            )?;
            prune_terminal_drop_upload_sessions_in_tx(&tx, &session.drop_id)?;
            tx.commit()?;
            changed
        };
        if changed != 1 {
            return Err(ApiError::Conflict);
        }
        let updated = self
            .get_drop_upload_session(session_id)?
            .ok_or(ApiError::NotFound)?;
        let receipt =
            self.insert_receipt("drop.upload.cancel", "public", Some(&session.drop_id))?;
        Ok((updated, receipt))
    }

    pub fn fail_drop_upload_session(
        &self,
        session_id: &str,
        error_code: &str,
    ) -> ApiResult<DropUploadRecord> {
        let error_code = validate_drop_upload_error_code(error_code)?;
        let now = Utc::now().to_rfc3339();
        let session = self
            .get_drop_upload_session(session_id)?
            .ok_or(ApiError::NotFound)?;
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute(
                "UPDATE drop_upload_sessions
                 SET status = 'failed', last_error_code = ?1, updated_at = ?2
                 WHERE id = ?3 AND status = 'active'",
                params![error_code, &now, session_id],
            )?;
            prune_terminal_drop_upload_sessions_in_tx(&tx, &session.drop_id)?;
            tx.commit()?;
        }
        self.get_drop_upload_session(session_id)?
            .ok_or(ApiError::NotFound)
    }
}

fn enforce_drop_upload_admission(
    tx: &rusqlite::Transaction<'_>,
    drop_id: &str,
    workspace_id: &str,
    transport_fingerprint: &str,
    declared_size: i64,
    policy: DropUploadAdmissionPolicy,
) -> ApiResult<()> {
    let (global_sessions, global_bytes): (i64, i64) = tx.query_row(
        "SELECT COUNT(*), COALESCE(SUM(
            CASE WHEN total_size > 0 THEN total_size ELSE 1 END
         ), 0)
         FROM drop_upload_sessions WHERE status = 'active'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (workspace_sessions, workspace_bytes): (i64, i64) = tx.query_row(
        "SELECT COUNT(*), COALESCE(SUM(
            CASE WHEN total_size > 0 THEN total_size ELSE 1 END
         ), 0)
         FROM drop_upload_sessions WHERE workspace_id = ?1 AND status = 'active'",
        params![workspace_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (drop_sessions, drop_bytes): (i64, i64) = tx.query_row(
        "SELECT COUNT(*), COALESCE(SUM(
            CASE WHEN total_size > 0 THEN total_size ELSE 1 END
         ), 0)
         FROM drop_upload_sessions WHERE drop_id = ?1 AND status = 'active'",
        params![drop_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (client_sessions, client_reserved): (i64, i64) = tx.query_row(
        "SELECT COUNT(*), COALESCE(SUM(
            CASE WHEN total_size > 0 THEN total_size ELSE 1 END
         ), 0)
         FROM drop_upload_sessions
         WHERE transport_fingerprint = ?1 AND status = 'active'",
        params![transport_fingerprint],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let global_completed_bytes: i64 = tx.query_row(
        "SELECT COALESCE(SUM(uploaded_bytes), 0) FROM drops",
        [],
        |row| row.get(0),
    )?;
    let workspace_completed_bytes: i64 = tx.query_row(
        "SELECT COALESCE(SUM(uploaded_bytes), 0) FROM drops WHERE workspace_id = ?1",
        params![workspace_id],
        |row| row.get(0),
    )?;
    let drop_completed_bytes: i64 = tx
        .query_row(
            "SELECT uploaded_bytes FROM drops WHERE id = ?1",
            params![drop_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(ApiError::NotFound)?;
    let global_bytes = global_bytes.saturating_add(global_completed_bytes);
    let workspace_bytes = workspace_bytes.saturating_add(workspace_completed_bytes);
    let drop_bytes = drop_bytes.saturating_add(drop_completed_bytes);

    let reservation = declared_size.max(1);
    if global_sessions >= policy.max_global_sessions.max(1)
        || workspace_sessions >= policy.max_workspace_sessions.max(1)
        || drop_sessions >= policy.max_drop_sessions.max(1)
        || client_sessions >= policy.max_client_sessions.max(1)
        || global_bytes.saturating_add(reservation) > policy.max_global_bytes.max(1)
        || workspace_bytes.saturating_add(reservation) > policy.max_workspace_bytes.max(1)
        || drop_bytes.saturating_add(reservation) > policy.max_drop_bytes.max(1)
        || client_reserved.saturating_add(reservation) > policy.max_client_reserved_bytes.max(1)
    {
        return Err(ApiError::TooManyRequests);
    }
    Ok(())
}

pub(super) fn prune_terminal_drop_upload_sessions_in_tx(
    tx: &rusqlite::Transaction<'_>,
    drop_id: &str,
) -> ApiResult<()> {
    tx.execute(
        "DELETE FROM drop_upload_sessions
         WHERE id IN (
             SELECT id FROM drop_upload_sessions
             WHERE drop_id = ?1 AND status IN ('canceled', 'failed')
             ORDER BY updated_at DESC, id DESC
             LIMIT -1 OFFSET ?2
         )",
        params![drop_id, MAX_TERMINAL_UPLOAD_SESSIONS_PER_DROP],
    )?;
    Ok(())
}

fn active_child_locked(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    parent_id: Option<&str>,
    name: &str,
) -> ApiResult<Option<DriveFile>> {
    let files = if let Some(parent_id) = parent_id {
        let mut statement = tx.prepare(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                    content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files
             WHERE workspace_id = ?1 AND parent_id = ?2 AND name = ?3 AND trashed = 0
             ORDER BY CASE WHEN kind = 'folder' THEN 0 ELSE 1 END, created_at ASC, id ASC
             LIMIT 2",
        )?;
        let files = statement
            .query_map(params![workspace_id, parent_id, name], row_to_file)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        files
    } else {
        let mut statement = tx.prepare(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                    content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files
             WHERE workspace_id = ?1 AND parent_id IS NULL AND name = ?2 AND trashed = 0
             ORDER BY CASE WHEN kind = 'folder' THEN 0 ELSE 1 END, created_at ASC, id ASC
             LIMIT 2",
        )?;
        let files = statement
            .query_map(params![workspace_id, name], row_to_file)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        files
    };
    match files.as_slice() {
        [] => Ok(None),
        [file] => Ok(Some(file.clone())),
        _ => Ok(None),
    }
}

pub(super) fn row_to_drop_upload_record(row: &Row<'_>) -> rusqlite::Result<DropUploadRecord> {
    Ok(DropUploadRecord {
        id: row.get(0)?,
        drop_id: row.get(1)?,
        workspace_id: row.get(2)?,
        client_fingerprint: row.get(3)?,
        transport_fingerprint: row.get(4)?,
        name: row.get(5)?,
        path: row.get(6)?,
        content_type: row.get(7)?,
        total_size: row.get(8)?,
        received_bytes: row.get(9)?,
        chunk_count: row.get(10)?,
        status: row.get(11)?,
        file_id: row.get(12)?,
        last_error_code: row.get(13)?,
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
        completed_at: row.get(16)?,
        canceled_at: row.get(17)?,
    })
}

fn validate_declared_content_type(value: &str) -> ApiResult<String> {
    let value = value.trim();
    let valid = !value.is_empty()
        && value.len() <= 255
        && value
            .split_once('/')
            .is_some_and(|(top, subtype)| is_mime_token(top) && is_mime_token(subtype));
    if !valid {
        return Err(ApiError::Validation(
            "content_type must be a valid MIME declaration up to 255 bytes".to_string(),
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn is_mime_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                )
        })
}

fn validate_drop_upload_error_code(value: &str) -> ApiResult<&str> {
    if matches!(
        value,
        "part_missing" | "part_size_mismatch" | "storage_error" | "stale_cleanup"
    ) {
        Ok(value)
    } else {
        Err(ApiError::Validation(
            "unsupported drop upload error code".to_string(),
        ))
    }
}
