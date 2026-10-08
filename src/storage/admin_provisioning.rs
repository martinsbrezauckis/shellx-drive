use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{DriveUser, HostedTenant, Receipt, Workspace},
};

use super::{
    authorization, insert_receipt_rows, new_receipt, normalize_storage_email,
    validate_non_empty_label, validate_workspace_name, Storage,
};

impl Storage {
    pub(crate) fn create_workspace_authorized(
        &self,
        name: &str,
        owner_email: &str,
        tenant_id: Option<&str>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(Workspace, DriveUser, Receipt)> {
        let name = validate_workspace_name(name)?;
        let owner_email = normalize_storage_email(owner_email)?;
        let now = Utc::now().to_rfc3339();
        let workspace = Workspace {
            id: Uuid::now_v7().to_string(),
            tenant_id: tenant_id.map(str::to_string),
            name,
            storage_mode: "open".to_string(),
            created_at: now.clone(),
            updated_at: now.clone(),
            archived: false,
            archived_at: None,
            role: None,
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        if let Some(tenant_id) = tenant_id {
            let exists = tx
                .query_row(
                    "SELECT 1 FROM tenants WHERE id = ?1",
                    params![tenant_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !exists {
                return Err(ApiError::NotFound);
            }
        }
        let owner_id = tx
            .query_row(
                "SELECT id FROM users WHERE email = ?1",
                params![&owner_email],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| Uuid::now_v7().to_string());
        tx.execute(
            "INSERT OR IGNORE INTO users (id, email, created_at) VALUES (?1, ?2, ?3)",
            params![&owner_id, &owner_email, &now],
        )?;
        let owner = tx.query_row(
            "SELECT id, email, created_at FROM users WHERE email = ?1",
            params![&owner_email],
            |row| {
                Ok(DriveUser {
                    id: row.get(0)?,
                    email: row.get(1)?,
                    created_at: row.get(2)?,
                })
            },
        )?;
        tx.execute(
            "INSERT INTO workspaces (id, tenant_id, name, storage_mode, created_at, updated_at)
             VALUES (?1, ?2, ?3, 'open', ?4, ?4)",
            params![&workspace.id, &workspace.tenant_id, &workspace.name, &now],
        )?;
        tx.execute(
            "INSERT INTO workspace_members (workspace_id, user_id, role)
             VALUES (?1, ?2, 'owner')",
            params![&workspace.id, &owner.id],
        )?;
        let receipt = new_receipt("workspace.create", &actor.email, Some(&workspace.id));
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((workspace, owner, receipt))
    }

    pub(crate) fn create_hosted_tenant_authorized(
        &self,
        name: &str,
        owner_email: &str,
        plan: &str,
        billing_status: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(HostedTenant, Receipt)> {
        let now = Utc::now().to_rfc3339();
        let tenant = HostedTenant {
            id: Uuid::now_v7().to_string(),
            name: validate_workspace_name(name)?,
            owner_email: normalize_storage_email(owner_email)?,
            plan: validate_non_empty_label(plan, "plan")?,
            billing_status: validate_non_empty_label(billing_status, "billing_status")?,
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let owner_id = tx
            .query_row(
                "SELECT id FROM users WHERE email = ?1",
                params![&tenant.owner_email],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| Uuid::now_v7().to_string());
        tx.execute(
            "INSERT OR IGNORE INTO users (id, email, created_at) VALUES (?1, ?2, ?3)",
            params![owner_id, &tenant.owner_email, &now],
        )?;
        tx.execute(
            "INSERT INTO tenants
                (id, name, owner_email, plan, billing_status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            params![
                &tenant.id,
                &tenant.name,
                &tenant.owner_email,
                &tenant.plan,
                &tenant.billing_status,
                &now
            ],
        )?;
        let receipt = new_receipt("hosted.tenant.create", &actor.email, Some(&tenant.id));
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((tenant, receipt))
    }
}
