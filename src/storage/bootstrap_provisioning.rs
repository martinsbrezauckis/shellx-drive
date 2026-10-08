//! Atomic first-run account and workspace provisioning.

use chrono::Utc;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::ensure_not_reserved_user_email,
    error::{ApiError, ApiResult},
    model::{AuthAccount, DriveUser, Receipt, Workspace},
};

use super::{
    human_item_grants::provisioning::{
        ensure_private_workspace_for_account_in_tx, register_private_workspace_in_tx,
    },
    insert_receipt_rows, new_receipt, normalize_storage_email, validate_workspace_name, Storage,
};

impl Storage {
    pub fn bootstrap_auth_account(
        &self,
        email: &str,
        password_hash: &str,
    ) -> ApiResult<(AuthAccount, Receipt)> {
        let email = normalize_storage_email(email)?;
        ensure_not_reserved_user_email(&email)?;
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (account, _owner, receipt) = insert_initial_account(&tx, &email, password_hash, &now)?;
        ensure_private_workspace_for_account_in_tx(&tx, &account.user_id, &now)?;
        tx.commit()?;
        Ok((account, receipt))
    }

    pub fn bootstrap_auth_account_with_workspace(
        &self,
        email: &str,
        password_hash: &str,
        workspace_name: &str,
        storage_mode: &str,
    ) -> ApiResult<(AuthAccount, Workspace, DriveUser, Receipt)> {
        let email = normalize_storage_email(email)?;
        ensure_not_reserved_user_email(&email)?;
        let workspace_name = validate_workspace_name(workspace_name)?;
        if storage_mode != "open" {
            return Err(ApiError::Validation(
                "storage_mode must be open".to_string(),
            ));
        }

        let now = Utc::now().to_rfc3339();
        let workspace = Workspace {
            id: Uuid::now_v7().to_string(),
            tenant_id: None,
            name: workspace_name,
            storage_mode: "open".to_string(),
            created_at: now.clone(),
            updated_at: now.clone(),
            archived: false,
            archived_at: None,
            role: None,
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (account, owner, _account_receipt) =
            insert_initial_account(&tx, &email, password_hash, &now)?;
        tx.execute(
            "INSERT INTO workspaces (id, tenant_id, name, storage_mode, created_at, updated_at)
             VALUES (?1, NULL, ?2, 'open', ?3, ?3)",
            params![&workspace.id, &workspace.name, &now],
        )?;
        tx.execute(
            "INSERT INTO workspace_members (workspace_id, user_id, role)
             VALUES (?1, ?2, 'owner')",
            params![&workspace.id, &owner.id],
        )?;
        register_private_workspace_in_tx(&tx, &account.user_id, &workspace.id, &now)?;
        let workspace_receipt = new_receipt("workspace.create", &email, Some(&workspace.id));
        insert_receipt_rows(&tx, &workspace_receipt)?;
        tx.commit()?;
        Ok((account, workspace, owner, workspace_receipt))
    }
}

fn insert_initial_account(
    tx: &Transaction<'_>,
    email: &str,
    password_hash: &str,
    now: &str,
) -> ApiResult<(AuthAccount, DriveUser, Receipt)> {
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM auth_accounts", [], |row| row.get(0))?;
    if count > 0 {
        return Err(ApiError::Conflict);
    }
    let user_id = tx
        .query_row(
            "SELECT id FROM users WHERE email = ?1",
            params![email],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    tx.execute(
        "INSERT OR IGNORE INTO users (id, email, created_at) VALUES (?1, ?2, ?3)",
        params![&user_id, email, now],
    )?;
    let owner = tx.query_row(
        "SELECT id, email, created_at FROM users WHERE id = ?1",
        params![&user_id],
        |row| {
            Ok(DriveUser {
                id: row.get(0)?,
                email: row.get(1)?,
                created_at: row.get(2)?,
            })
        },
    )?;
    tx.execute(
        "INSERT INTO auth_accounts (
            user_id, email, password_hash, is_admin, totp_secret,
            totp_enabled, recovery_code_hashes, disabled_at,
            created_at, updated_at
         ) VALUES (?1, ?2, ?3, 1, NULL, 0, '[]', NULL, ?4, ?4)",
        params![&user_id, email, password_hash, now],
    )?;
    let receipt = new_receipt("auth.account.create", email, Some(email));
    insert_receipt_rows(tx, &receipt)?;
    Ok((
        AuthAccount {
            user_id,
            email: email.to_string(),
            is_admin: true,
            totp_enabled: false,
            recovery_codes_remaining: 0,
            disabled: false,
            created_at: now.to_string(),
            updated_at: now.to_string(),
        },
        owner,
        receipt,
    ))
}
