use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{Receipt, UploadSession},
};

use super::{lifecycle::prune_terminal_upload_sessions_in_tx, UploadAdmissionPolicy};
use crate::storage::quota_reservations::{
    enforce_workspace_quota_with_reservations, ReservationExclusions,
};

pub(super) fn ensure_upload_finalizer_permission(
    tx: &rusqlite::Transaction<'_>,
    session: &UploadSession,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    if let Some(target_file_id) = session.target_file_id.as_deref() {
        crate::storage::authorization::ensure_source_credential_active(
            tx,
            actor,
            source_credential,
        )?;
        return crate::storage::human_item_grants::access::resolve_item_response_access_in_tx(
            tx,
            target_file_id,
            actor,
            WorkspacePermission::Write,
        )
        .map(|_| ());
    }
    crate::storage::human_item_grants::access::ensure_item_destination_authorized_in_tx(
        tx,
        &session.workspace_id,
        session.parent_id.as_deref(),
        actor,
        source_credential,
    )
}

pub(super) fn enforce_upload_completion_quota(
    tx: &rusqlite::Transaction<'_>,
    quota_bytes: i64,
    workspace_id: &str,
    replaced_file_id: Option<&str>,
    content_bytes: i64,
    session_id: &str,
) -> ApiResult<()> {
    if content_bytes < 0 {
        return Err(ApiError::Validation(
            "content_bytes must not be negative".to_string(),
        ));
    }
    let new_charge = if let Some(file_id) = replaced_file_id {
        let cover_bytes: i64 = tx
            .query_row(
                "SELECT cover_bytes
                 FROM files
                 WHERE id = ?1 AND workspace_id = ?2 AND trashed = 0",
                params![file_id, workspace_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(ApiError::Conflict)?;
        content_bytes.max(1).saturating_add(cover_bytes)
    } else {
        content_bytes.max(1)
    };
    let _ = quota_bytes;
    enforce_workspace_quota_with_reservations(
        tx,
        workspace_id,
        new_charge,
        ReservationExclusions {
            upload_session_id: Some(session_id),
            drop_upload_session_id: None,
        },
    )
}

pub(super) fn complete_upload_session_in_tx(
    tx: &rusqlite::Transaction<'_>,
    session: &UploadSession,
    receipt: &Receipt,
) -> ApiResult<()> {
    if tx.execute(
        "UPDATE upload_sessions
         SET received_bytes = ?1, completed = 1, file_id = ?2, updated_at = ?3,
             completion_receipt_id = ?4, completion_current_revision = ?5
         WHERE id = ?6 AND completed = 0 AND canceled = 0",
        params![
            session.received_bytes,
            &session.file_id,
            &session.updated_at,
            &session.completion_receipt_id,
            session.completion_current_revision,
            &session.id,
        ],
    )? != 1
    {
        return Err(ApiError::Conflict);
    }
    insert_upload_receipt_in_tx(tx, receipt)?;
    prune_terminal_upload_sessions_in_tx(tx, &session.workspace_id)
}

pub(super) fn insert_upload_receipt_in_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt: &Receipt,
) -> ApiResult<()> {
    tx.execute(
        "INSERT INTO receipts (id, kind, actor, target_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            &receipt.id,
            &receipt.kind,
            &receipt.actor,
            &receipt.target_id,
            &receipt.created_at,
        ],
    )?;
    tx.execute(
        "INSERT INTO activity (id, kind, actor, target_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            Uuid::now_v7().to_string(),
            &receipt.kind,
            &receipt.actor,
            &receipt.target_id,
            &receipt.created_at,
        ],
    )?;
    crate::storage::record_sync_change_for_receipt(tx, receipt)?;
    Ok(())
}

pub(super) fn enforce_upload_admission(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    actor_email: &str,
    declared_size: i64,
    quota_reservation_bytes: i64,
    policy: UploadAdmissionPolicy,
) -> ApiResult<()> {
    let (global_sessions, global_reserved): (i64, i64) = tx.query_row(
        "SELECT COUNT(*), COALESCE(SUM(CASE
            WHEN COALESCE(total_size, received_bytes) > 0
            THEN COALESCE(total_size, received_bytes) ELSE 1 END), 0)
         FROM upload_sessions WHERE completed = 0 AND canceled = 0",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (workspace_sessions, workspace_reserved): (i64, i64) = tx.query_row(
        "SELECT COUNT(*), COALESCE(SUM(CASE
            WHEN COALESCE(total_size, received_bytes) > 0
            THEN COALESCE(total_size, received_bytes) ELSE 1 END), 0)
         FROM upload_sessions
         WHERE workspace_id = ?1 AND completed = 0 AND canceled = 0",
        params![workspace_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (actor_sessions, actor_reserved): (i64, i64) = tx.query_row(
        "SELECT COUNT(*), COALESCE(SUM(CASE
            WHEN COALESCE(total_size, received_bytes) > 0
            THEN COALESCE(total_size, received_bytes) ELSE 1 END), 0)
         FROM upload_sessions
         WHERE actor_email = ?1 AND completed = 0 AND canceled = 0",
        params![actor_email],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let reservation = declared_size.max(1);
    if global_sessions >= policy.max_global_sessions
        || workspace_sessions >= policy.max_workspace_sessions
        || actor_sessions >= policy.max_actor_sessions
        || global_reserved.saturating_add(reservation) > policy.max_global_reserved_bytes
        || workspace_reserved.saturating_add(reservation) > policy.max_workspace_reserved_bytes
        || actor_reserved.saturating_add(reservation) > policy.max_actor_reserved_bytes
    {
        return Err(ApiError::TooManyRequests);
    }

    enforce_workspace_quota_with_reservations(
        tx,
        workspace_id,
        quota_reservation_bytes,
        ReservationExclusions::default(),
    )
}
