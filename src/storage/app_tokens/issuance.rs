use chrono::Utc;
use rusqlite::{params, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{AppToken, Receipt},
};

use super::super::{authorization, insert_receipt_rows, new_receipt, Storage};

impl Storage {
    /// Generic storage issuance remains immediately usable. It never receives
    /// or returns plaintext token material, so callers that expose a bearer
    /// must use the route-only pending-publication flow below instead.
    #[allow(clippy::too_many_arguments)]
    pub fn create_app_token(
        &self,
        label: &str,
        actor_email: &str,
        token_hash: &str,
        workspace_ids: &[String],
        expires_at: &str,
        admin_actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(AppToken, Receipt)> {
        let app_token = new_app_token(label, actor_email, workspace_ids, expires_at)?;
        let receipt = new_receipt("app_token.create", &admin_actor.email, Some(&app_token.id));
        self.insert_app_token(
            &app_token,
            token_hash,
            false,
            Some(&receipt),
            admin_actor,
            source_credential,
        )?;
        Ok((app_token, receipt))
    }

    /// Store an inactive issuance intent for the HTTP bearer route. It cannot
    /// authenticate or appear in normal token listings until publication wins
    /// the final source-admin recheck transaction.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_pending_app_token_publication(
        &self,
        label: &str,
        actor_email: &str,
        token_hash: &str,
        workspace_ids: &[String],
        expires_at: &str,
        admin_actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(AppToken, Receipt)> {
        let app_token = new_app_token(label, actor_email, workspace_ids, expires_at)?;
        let receipt = new_receipt("app_token.create", &admin_actor.email, Some(&app_token.id));
        self.insert_app_token(
            &app_token,
            token_hash,
            true,
            None,
            admin_actor,
            source_credential,
        )?;
        Ok((app_token, receipt))
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_app_token(
        &self,
        app_token: &AppToken,
        token_hash: &str,
        publication_pending: bool,
        receipt: Option<&Receipt>,
        admin_actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let workspace_ids_json =
            serde_json::to_string(&app_token.workspace_ids).map_err(|error| {
                ApiError::Validation(format!("failed to encode app token workspaces: {error}"))
            })?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, admin_actor, source_credential)?;
        tx.execute(
            "INSERT INTO app_tokens (
                id, label, actor_email, token_hash, workspace_ids_json,
                expires_at, last_used_at, revoked_at, created_at, publication_pending
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, ?7, ?8)",
            params![
                &app_token.id,
                &app_token.label,
                &app_token.actor_email,
                token_hash,
                workspace_ids_json,
                &app_token.expires_at,
                &app_token.created_at,
                publication_pending as i64,
            ],
        )?;
        if let Some(receipt) = receipt {
            insert_receipt_rows(&tx, receipt)?;
        }
        tx.commit()?;
        Ok(())
    }
}

fn new_app_token(
    label: &str,
    actor_email: &str,
    workspace_ids: &[String],
    expires_at: &str,
) -> ApiResult<AppToken> {
    if workspace_ids.is_empty() {
        return Err(ApiError::Validation(
            "app token workspace scope must not be empty".to_string(),
        ));
    }
    Ok(AppToken {
        id: Uuid::now_v7().to_string(),
        label: label.to_string(),
        actor_email: actor_email.to_string(),
        workspace_ids: workspace_ids.to_vec(),
        expires_at: expires_at.to_string(),
        last_used_at: None,
        revoked_at: None,
        created_at: Utc::now().to_rfc3339(),
        revoked: false,
    })
}
