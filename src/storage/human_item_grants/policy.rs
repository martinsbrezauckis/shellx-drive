use chrono::Utc;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    error::ApiResult,
    model::{EveryoneGrantPolicy, Receipt, UpdateEveryoneGrantPolicyRequest},
};

use super::super::{authorization, insert_receipt_rows, new_receipt, Storage};

pub(in crate::storage) const EVERYONE_GRANTS_ENABLED_KEY: &str =
    "human_item_grants.everyone_enabled";

impl Storage {
    pub(crate) fn everyone_grant_policy(&self) -> ApiResult<EveryoneGrantPolicy> {
        let conn = self.conn.lock().unwrap();
        policy_in_conn(&conn)
    }

    pub(crate) fn update_everyone_grant_policy_authorized(
        &self,
        request: UpdateEveryoneGrantPolicyRequest,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(EveryoneGrantPolicy, Receipt)> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let policy = EveryoneGrantPolicy {
            everyone_grants_enabled: request.everyone_grants_enabled,
            updated_at: Utc::now().to_rfc3339(),
        };
        tx.execute(
            "INSERT INTO server_settings (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![
                EVERYONE_GRANTS_ENABLED_KEY,
                policy.everyone_grants_enabled.to_string(),
                &policy.updated_at
            ],
        )?;
        let receipt = new_receipt(
            "human_item_grant.everyone_policy.update",
            &actor.email,
            Some(EVERYONE_GRANTS_ENABLED_KEY),
        );
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((policy, receipt))
    }
}

pub(super) fn ensure_everyone_grants_enabled_in_tx(tx: &Transaction<'_>) -> ApiResult<()> {
    if everyone_grants_enabled_in_tx(tx)? {
        return Ok(());
    }
    Err(crate::error::ApiError::Validation(
        "everyone item grants are disabled by the server administrator".to_string(),
    ))
}

fn policy_in_conn(conn: &rusqlite::Connection) -> ApiResult<EveryoneGrantPolicy> {
    let value = conn
        .query_row(
            "SELECT value, updated_at FROM server_settings WHERE key = ?1",
            [EVERYONE_GRANTS_ENABLED_KEY],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    Ok(match value {
        Some((value, updated_at)) => EveryoneGrantPolicy {
            everyone_grants_enabled: value == "true",
            updated_at,
        },
        None => EveryoneGrantPolicy {
            everyone_grants_enabled: false,
            updated_at: String::new(),
        },
    })
}

fn everyone_grants_enabled_in_tx(tx: &Transaction<'_>) -> ApiResult<bool> {
    let value = tx
        .query_row(
            "SELECT value FROM server_settings WHERE key = ?1",
            [EVERYONE_GRANTS_ENABLED_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(value.as_deref() == Some("true"))
}
