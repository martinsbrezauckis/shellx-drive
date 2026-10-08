//! Application-token authentication, listing, and revocation.

mod issuance;
mod publication;

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{AppToken, Receipt},
};

use super::{authorization, row_to_app_token, Storage, MAX_DEBUG_LIST_ROWS};

impl Storage {
    pub fn list_app_tokens(&self) -> ApiResult<Vec<AppToken>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, label, actor_email, workspace_ids_json, expires_at,
                    last_used_at, revoked_at, created_at
             FROM app_tokens
             WHERE publication_pending = 0
             ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![MAX_DEBUG_LIST_ROWS], row_to_app_token)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn authenticate_app_token(
        &self,
        token_hash: &str,
        now_epoch: i64,
    ) -> ApiResult<Option<AppToken>> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let app_token = conn
            .query_row(
                "SELECT id, label, actor_email, workspace_ids_json, expires_at,
                        last_used_at, revoked_at, created_at
                 FROM app_tokens WHERE token_hash = ?1 AND publication_pending = 0",
                params![token_hash],
                row_to_app_token,
            )
            .optional()?;
        let Some(mut app_token) = app_token else {
            return Ok(None);
        };
        let expires_at = DateTime::parse_from_rfc3339(&app_token.expires_at)
            .map_err(|_| ApiError::Unauthenticated)?
            .timestamp();
        if app_token.revoked || expires_at <= now_epoch || app_token.workspace_ids.is_empty() {
            return Ok(None);
        }
        conn.execute(
            "UPDATE app_tokens SET last_used_at = ?2 WHERE id = ?1",
            params![app_token.id, now],
        )?;
        app_token.last_used_at = Some(now);
        Ok(Some(app_token))
    }

    pub fn revoke_app_token(
        &self,
        id: &str,
        admin_actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(AppToken, Receipt)> {
        let revoked_at = Utc::now().to_rfc3339();
        let app_token = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_admin_authorized(&tx, admin_actor, source_credential)?;
            let changed = tx.execute(
                "UPDATE app_tokens
                 SET revoked_at = COALESCE(revoked_at, ?2)
                 WHERE id = ?1",
                params![id, revoked_at],
            )?;
            if changed == 0 {
                return Err(ApiError::NotFound);
            }
            tx.execute(
                "UPDATE office_edit_sessions
                 SET used_at = COALESCE(used_at, ?2)
                 WHERE source_credential_kind = 'app_token'
                   AND source_credential_id = ?1 AND used_at IS NULL",
                params![id, revoked_at],
            )?;
            let app_token = tx.query_row(
                "SELECT id, label, actor_email, workspace_ids_json, expires_at,
                        last_used_at, revoked_at, created_at
                 FROM app_tokens WHERE id = ?1",
                params![id],
                row_to_app_token,
            )?;
            tx.commit()?;
            app_token
        };
        let receipt = self.insert_receipt("app_token.revoke", &admin_actor.email, Some(id))?;
        Ok((app_token, receipt))
    }
}
