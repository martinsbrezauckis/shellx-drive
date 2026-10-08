use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission, WorkspaceRole},
    error::{ApiError, ApiResult},
    model::{CreateHumanItemGrantRequest, HumanItemGrant, Receipt},
};

use super::super::{
    authorization, insert_receipt_rows, new_receipt, normalize_storage_email, Storage,
};
use super::{
    access::resolve_item_response_access_in_tx,
    policy::ensure_everyone_grants_enabled_in_tx,
    retention::{
        ensure_current_grant_capacity_in_tx, prune_retained_grant_history_in_tx,
        retire_expired_grants_for_workspace_in_tx,
    },
};

impl Storage {
    pub fn create_human_item_grant(
        &self,
        root_file_id: &str,
        request: &CreateHumanItemGrantRequest,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(HumanItemGrant, Receipt)> {
        let role = parse_collaborator_role(&request.role)?;
        let now = Utc::now().to_rfc3339();
        let expires_at = normalize_expiry(request.expires_at.as_deref(), &now)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let workspace_id = ensure_share_manager_in_tx(&tx, root_file_id, actor, source_credential)?;
        retire_expired_grants_for_workspace_in_tx(&tx, &workspace_id)?;
        let (principal_ref, principal_label) = normalize_principal_in_tx(
            &tx,
            &request.principal_kind,
            request.principal_ref.as_deref(),
        )?;
        if request.principal_kind == "everyone" {
            // This is immediately before replacement/revocation publication,
            // so a policy change cannot turn a POST into an unguarded grant.
            ensure_everyone_grants_enabled_in_tx(&tx)?;
        }
        tx.execute(
            "UPDATE human_item_grants
             SET revoked_at = ?1, updated_at = ?1
             WHERE root_file_id = ?2 AND principal_kind = ?3
               AND COALESCE(principal_ref, '') = COALESCE(?4, '')
               AND revoked_at IS NULL",
            params![&now, root_file_id, &request.principal_kind, &principal_ref],
        )?;
        prune_retained_grant_history_in_tx(&tx, &workspace_id)?;
        ensure_current_grant_capacity_in_tx(
            &tx,
            &workspace_id,
            root_file_id,
            &request.principal_kind,
            principal_ref.as_deref(),
            &now,
        )?;
        let grant = HumanItemGrant {
            id: Uuid::now_v7().to_string(),
            workspace_id,
            root_file_id: root_file_id.to_string(),
            principal_kind: request.principal_kind.clone(),
            principal_ref,
            principal_label,
            role: role.as_db_str().to_string(),
            created_by: actor.email.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
            expires_at,
            revoked_at: None,
        };
        tx.execute(
            "INSERT INTO human_item_grants (
                id, workspace_id, root_file_id, principal_kind, principal_ref,
                role, created_by, created_at, updated_at, expires_at, revoked_at, publication_pending
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, NULL, 0)",
            params![&grant.id, &grant.workspace_id, &grant.root_file_id, &grant.principal_kind,
                &grant.principal_ref, &grant.role, &grant.created_by, &grant.created_at, &grant.expires_at],
        )?;
        let receipt = new_receipt("human_item_grant.create", &actor.email, Some(&grant.id));
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((grant, receipt))
    }

    pub fn update_human_item_grant(
        &self,
        grant_id: &str,
        role: Option<&str>,
        expires_at: Option<Option<&str>>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(HumanItemGrant, Receipt)> {
        let role = role.map(parse_collaborator_role).transpose()?;
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = select_active_grant_in_tx(&tx, grant_id)?;
        ensure_share_manager_in_tx(&tx, &current.root_file_id, actor, source_credential)
            .map_err(conceal_grant_record_denial)?;
        if current.principal_kind == "everyone" {
            // Existing grants remain effective and revocable when disabled,
            // but their role or expiry cannot be changed until re-enabled.
            ensure_everyone_grants_enabled_in_tx(&tx)?;
        }
        let next_role = role.unwrap_or_else(|| {
            WorkspaceRole::parse(&current.role).expect("stored role is constrained")
        });
        let next_expiry = match expires_at {
            Some(value) => normalize_expiry(value, &now)?,
            None => current.expires_at.clone(),
        };
        tx.execute(
            "UPDATE human_item_grants SET role = ?1, expires_at = ?2, updated_at = ?3
             WHERE id = ?4 AND revoked_at IS NULL",
            params![next_role.as_db_str(), &next_expiry, &now, grant_id],
        )?;
        let grant = HumanItemGrant {
            role: next_role.as_db_str().to_string(),
            expires_at: next_expiry,
            updated_at: now.clone(),
            ..current
        };
        let receipt = new_receipt("human_item_grant.update", &actor.email, Some(grant_id));
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((grant, receipt))
    }

    pub fn revoke_human_item_grant(
        &self,
        grant_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = select_active_grant_in_tx(&tx, grant_id)?;
        ensure_share_manager_in_tx(&tx, &current.root_file_id, actor, source_credential)
            .map_err(conceal_grant_record_denial)?;
        if tx.execute(
            "UPDATE human_item_grants SET revoked_at = ?1, updated_at = ?1
             WHERE id = ?2 AND revoked_at IS NULL",
            params![&now, grant_id],
        )? != 1
        {
            return Err(ApiError::NotFound);
        }
        prune_retained_grant_history_in_tx(&tx, &current.workspace_id)?;
        let receipt = new_receipt("human_item_grant.revoke", &actor.email, Some(grant_id));
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }

    pub fn list_human_item_grants(&self, root_file_id: &str) -> ApiResult<Vec<HumanItemGrant>> {
        self.retire_expired_human_item_grants()?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let grants = list_current_human_item_grants_in_tx(&tx, root_file_id)?;
        tx.commit()?;
        Ok(grants)
    }
}

const GRANT_SELECT_CURRENT: &str =
    "SELECT g.id, g.workspace_id, g.root_file_id, g.principal_kind, g.principal_ref,
            COALESCE(account.email, groups.name, 'Everyone in this Drive'),
            g.role, g.created_by, g.created_at, g.updated_at, g.expires_at, g.revoked_at
     FROM human_item_grants g
     LEFT JOIN users account ON g.principal_kind = 'account' AND account.id = g.principal_ref
     LEFT JOIN \"groups\" groups ON g.principal_kind = 'group' AND groups.id = g.principal_ref
     WHERE g.root_file_id = ?1 AND g.revoked_at IS NULL AND g.publication_pending = 0
       AND (g.expires_at IS NULL OR julianday(g.expires_at) > julianday('now'))
     ORDER BY g.created_at ASC, g.id ASC LIMIT 101";

pub(super) fn list_current_human_item_grants_in_tx(
    tx: &Transaction<'_>,
    root_file_id: &str,
) -> ApiResult<Vec<HumanItemGrant>> {
    let mut statement = tx.prepare(GRANT_SELECT_CURRENT)?;
    let rows = statement.query_map([root_file_id], row_to_human_item_grant)?;
    let grants = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    if grants.len() > 100 {
        return Err(ApiError::PayloadTooLarge(
            "item grant listing exceeds 100 rows".to_string(),
        ));
    }
    Ok(grants)
}

fn ensure_share_manager_in_tx(
    tx: &rusqlite::Transaction<'_>,
    root_file_id: &str,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<String> {
    authorization::ensure_source_credential_active(tx, actor, source_credential)?;
    let workspace_id =
        resolve_item_response_access_in_tx(tx, root_file_id, actor, WorkspacePermission::Read)?
            .workspace_id;
    if actor
        .allowed_workspace_ids
        .as_ref()
        .is_some_and(|ids| !ids.contains(&workspace_id))
    {
        return Err(ApiError::Forbidden);
    }
    // Item Editor means content edit only.  Delegating an item grant remains a
    // whole-workspace owner/admin operation and can never be inherited from a
    // human item grant (nor from generic WorkspacePermission::Manage).
    if !actor.is_admin
        && !super::access::whole_workspace_role_in_tx(tx, &workspace_id, &actor.email)?
            .is_some_and(|role| role == WorkspaceRole::Owner)
    {
        return Err(ApiError::Forbidden);
    }
    Ok(workspace_id)
}

fn conceal_grant_record_denial(error: ApiError) -> ApiError {
    match error {
        ApiError::Forbidden => ApiError::NotFound,
        other => other,
    }
}

fn normalize_principal_in_tx(
    tx: &rusqlite::Transaction<'_>,
    kind: &str,
    principal_ref: Option<&str>,
) -> ApiResult<(Option<String>, String)> {
    match kind {
        "everyone" => {
            if principal_ref.is_some_and(|value| !value.trim().is_empty()) {
                return Err(ApiError::Validation(
                    "everyone grants must not include a principal_ref".to_string(),
                ));
            }
            Ok((None, "Everyone in this Drive".to_string()))
        }
        "account" => {
            let email = normalize_storage_email(principal_ref.ok_or_else(|| {
                ApiError::Validation("account grants require principal_ref".to_string())
            })?)?;
            tx.query_row(
                "SELECT accounts.user_id, accounts.email FROM auth_accounts accounts
                 WHERE accounts.email = ?1 AND accounts.disabled_at IS NULL",
                [&email],
                |row| Ok((Some(row.get(0)?), row.get(1)?)),
            )
            .optional()?
            .ok_or(ApiError::NotFound)
        }
        "group" => {
            let group_id = principal_ref
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    ApiError::Validation("group grants require principal_ref".to_string())
                })?;
            tx.query_row(
                "SELECT id, name FROM \"groups\" WHERE id = ?1",
                [group_id],
                |row| Ok((Some(row.get(0)?), row.get(1)?)),
            )
            .optional()?
            .ok_or(ApiError::NotFound)
        }
        _ => Err(ApiError::Validation(
            "principal_kind must be account, group, or everyone".to_string(),
        )),
    }
}

fn parse_collaborator_role(value: &str) -> ApiResult<WorkspaceRole> {
    match WorkspaceRole::parse(value.trim()) {
        Some(WorkspaceRole::Viewer) => Ok(WorkspaceRole::Viewer),
        Some(WorkspaceRole::Editor) => Ok(WorkspaceRole::Editor),
        _ => Err(ApiError::Validation(
            "human item grant role must be viewer or editor".to_string(),
        )),
    }
}

fn normalize_expiry(value: Option<&str>, now: &str) -> ApiResult<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let expiry = DateTime::parse_from_rfc3339(value)
        .map_err(|_| ApiError::Validation("expires_at must be RFC3339".to_string()))?
        .with_timezone(&Utc);
    let now = DateTime::parse_from_rfc3339(now)
        .map_err(|_| ApiError::Validation("invalid server time".to_string()))?;
    if expiry <= now {
        return Err(ApiError::Validation(
            "expires_at must be in the future".to_string(),
        ));
    }
    Ok(Some(expiry.to_rfc3339()))
}

fn select_active_grant_in_tx(
    tx: &rusqlite::Transaction<'_>,
    grant_id: &str,
) -> ApiResult<HumanItemGrant> {
    tx.query_row(
        "SELECT g.id, g.workspace_id, g.root_file_id, g.principal_kind, g.principal_ref,
                COALESCE(account.email, groups.name, 'Everyone in this Drive'),
                g.role, g.created_by, g.created_at, g.updated_at, g.expires_at, g.revoked_at
         FROM human_item_grants g
         LEFT JOIN users account ON g.principal_kind = 'account' AND account.id = g.principal_ref
         LEFT JOIN \"groups\" groups ON g.principal_kind = 'group' AND groups.id = g.principal_ref
         WHERE g.id = ?1 AND g.revoked_at IS NULL AND g.publication_pending = 0",
        [grant_id],
        row_to_human_item_grant,
    )
    .optional()
    .map_err(ApiError::from)?
    .ok_or(ApiError::NotFound)
}

pub(super) fn row_to_human_item_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<HumanItemGrant> {
    Ok(HumanItemGrant {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        root_file_id: row.get(2)?,
        principal_kind: row.get(3)?,
        principal_ref: row.get(4)?,
        principal_label: row.get(5)?,
        role: row.get(6)?,
        created_by: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        expires_at: row.get(10)?,
        revoked_at: row.get(11)?,
    })
}
