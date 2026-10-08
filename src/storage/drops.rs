use chrono::{Datelike, Duration, Utc};
use rusqlite::{params, OptionalExtension};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{DropLink, Receipt},
    workspace_policy::validate_drop_update_policy,
};

#[cfg(test)]
mod expiry_tests;
mod preflight;
mod publication;

use super::{
    auth_throttle::clear_public_capability_password_budget_in_tx,
    authorization::ensure_workspace_authorized, row_to_drop_record,
    workspace_policy_in_transaction, DropRecord, PublicCapabilityKind, Storage,
};

const MAX_ACTIVE_DROPS_PER_WORKSPACE: i64 = 64;
const MAX_TERMINAL_DROPS_PER_WORKSPACE: i64 = 256;
const MAX_WORKSPACE_DROP_ROWS: i64 =
    MAX_ACTIVE_DROPS_PER_WORKSPACE + MAX_TERMINAL_DROPS_PER_WORKSPACE;

fn drop_expiry_from_ttl(seconds: i64) -> ApiResult<String> {
    if seconds <= 0 {
        return Err(ApiError::Validation(
            "drop ttl must be positive".to_string(),
        ));
    }
    let expiry = Duration::try_seconds(seconds)
        .and_then(|duration| Utc::now().checked_add_signed(duration))
        .filter(|expiry| expiry.year() <= 9999)
        .ok_or_else(|| ApiError::Validation("drop ttl is outside supported range".to_string()))?;
    Ok(expiry.to_rfc3339())
}

pub struct DropCreateFields<'a> {
    pub workspace_id: &'a str,
    pub name: &'a str,
    pub password_hash: &'a str,
    pub password_required: bool,
    pub expires_in_seconds: i64,
}

pub struct DropUpdateFields<'a> {
    pub name: Option<&'a str>,
    pub password_hash: Option<&'a str>,
    pub password_required: Option<bool>,
    pub expires_in_seconds: Option<i64>,
}

impl Storage {
    pub fn create_drop(
        &self,
        fields: DropCreateFields<'_>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DropLink, Receipt)> {
        let drop = publication::new_drop(&fields)?;
        self.insert_drop_with_publication_state(&drop, &fields, false, actor, source_credential)?;
        let receipt = self.insert_receipt("drop.create", &actor.email, Some(&drop.id))?;
        Ok((drop, receipt))
    }

    pub fn get_drop(&self, drop_id: &str) -> ApiResult<Option<DropRecord>> {
        let conn = self.conn.lock().unwrap();
        let record = conn
            .query_row(
                "SELECT id, workspace_id, name, password_hash, expires_at, revoked, created_at,
                        upload_count, last_uploaded_at, inbox_file_id, password_required
                 FROM drops WHERE id = ?1 AND publication_pending = 0",
                params![drop_id],
                row_to_drop_record,
            )
            .optional()?;
        Ok(record)
    }

    pub fn list_workspace_drops(&self, workspace_id: &str) -> ApiResult<Vec<DropLink>> {
        self.workspace_storage_mode(workspace_id)?;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, name, password_hash, expires_at, revoked, created_at,
                    upload_count, last_uploaded_at, inbox_file_id, password_required
             FROM drops
             WHERE workspace_id = ?1 AND publication_pending = 0
             ORDER BY created_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![workspace_id, MAX_WORKSPACE_DROP_ROWS],
            row_to_drop_record,
        )?;
        Ok(rows
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|record| record.drop)
            .collect())
    }

    pub fn list_all_drops_bounded(&self, limit: usize) -> ApiResult<Vec<DropLink>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX).max(1);
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, name, password_hash, expires_at, revoked, created_at,
                    upload_count, last_uploaded_at, inbox_file_id, password_required
             FROM drops
             WHERE publication_pending = 0
             ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], row_to_drop_record)?;
        Ok(rows
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|record| record.drop)
            .collect())
    }

    pub fn list_all_drops(&self) -> ApiResult<Vec<DropLink>> {
        self.list_all_drops_bounded(1_000)
    }

    pub fn update_drop(
        &self,
        drop_id: &str,
        fields: DropUpdateFields<'_>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DropLink, Receipt, Vec<String>)> {
        self.get_drop(drop_id)?.ok_or(ApiError::NotFound)?;
        let expires_at = fields
            .expires_in_seconds
            .map(drop_expiry_from_ttl)
            .transpose()?;
        let canceled_session_ids = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let workspace_id = tx
                .query_row(
                    "SELECT workspace_id FROM drops WHERE id = ?1",
                    params![drop_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            ensure_workspace_authorized(
                &tx,
                &workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
            let policy = workspace_policy_in_transaction(&tx, &workspace_id)?;
            validate_drop_update_policy(
                &policy,
                fields.password_required,
                fields.expires_in_seconds,
            )?;
            let mut canceled_session_ids = Vec::new();
            if let Some(password_hash) = fields.password_hash {
                {
                    let mut statement = tx.prepare(
                        "SELECT id FROM drop_upload_sessions
                         WHERE drop_id = ?1 AND status = 'active'
                         ORDER BY id ASC",
                    )?;
                    canceled_session_ids = statement
                        .query_map(params![drop_id], |row| row.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                }
                if tx.execute(
                    "UPDATE drops
                     SET name = COALESCE(?1, name),
                         password_hash = ?2,
                         password_required = ?5,
                         expires_at = COALESCE(?3, expires_at)
                     WHERE id = ?4",
                    params![
                        fields.name,
                        password_hash,
                        expires_at,
                        drop_id,
                        fields.password_required.unwrap_or(true) as i64
                    ],
                )? != 1
                {
                    return Err(ApiError::NotFound);
                }
                let now = Utc::now().to_rfc3339();
                tx.execute(
                    "UPDATE drop_upload_sessions
                     SET status = 'canceled', canceled_at = ?1, updated_at = ?1,
                         last_error_code = 'drop_password_rotated'
                     WHERE drop_id = ?2 AND status = 'active'",
                    params![&now, drop_id],
                )?;
                clear_public_capability_password_budget_in_tx(
                    &tx,
                    PublicCapabilityKind::Drop,
                    drop_id,
                )?;
            } else {
                if tx.execute(
                    "UPDATE drops
                     SET name = COALESCE(?1, name),
                         expires_at = COALESCE(?2, expires_at)
                     WHERE id = ?3",
                    params![fields.name, expires_at, drop_id],
                )? != 1
                {
                    return Err(ApiError::NotFound);
                }
            }
            tx.commit()?;
            canceled_session_ids
        };
        let drop = self.get_drop(drop_id)?.ok_or(ApiError::NotFound)?.drop;
        let receipt = self.insert_receipt("drop.update", &actor.email, Some(drop_id))?;
        Ok((drop, receipt, canceled_session_ids))
    }

    pub fn revoke_drop(
        &self,
        drop_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DropLink, Receipt, Vec<String>)> {
        let now = Utc::now().to_rfc3339();
        let canceled_session_ids = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let workspace_id = tx
                .query_row(
                    "SELECT workspace_id FROM drops WHERE id = ?1",
                    params![drop_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            ensure_workspace_authorized(
                &tx,
                &workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
            if tx.execute(
                "UPDATE drops SET revoked = 1 WHERE id = ?1",
                params![drop_id],
            )? != 1
            {
                return Err(ApiError::NotFound);
            }
            let session_ids = {
                let mut statement = tx.prepare(
                    "SELECT id FROM drop_upload_sessions
                     WHERE drop_id = ?1 AND status = 'active'
                     ORDER BY id ASC",
                )?;
                let rows = statement
                    .query_map(params![drop_id], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                rows
            };
            tx.execute(
                "UPDATE drop_upload_sessions
                 SET status = 'canceled', canceled_at = ?1, updated_at = ?1,
                     last_error_code = 'drop_revoked'
                 WHERE drop_id = ?2 AND status = 'active'",
                params![&now, drop_id],
            )?;
            tx.commit()?;
            session_ids
        };
        let drop = self.get_drop(drop_id)?.ok_or(ApiError::NotFound)?.drop;
        let receipt = self.insert_receipt("drop.revoke", &actor.email, Some(drop_id))?;
        Ok((drop, receipt, canceled_session_ids))
    }
}

fn prune_terminal_workspace_drops(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    now: &str,
) -> ApiResult<()> {
    tx.execute(
        "DELETE FROM drops WHERE id IN (
             SELECT id FROM drops
             WHERE workspace_id = ?1 AND publication_pending = 0
               AND (revoked != 0 OR expires_at <= ?2)
             ORDER BY created_at DESC, id DESC
             LIMIT -1 OFFSET ?3
         )",
        params![workspace_id, now, MAX_TERMINAL_DROPS_PER_WORKSPACE],
    )?;
    Ok(())
}
