use rusqlite::{params, OptionalExtension, Transaction};

use crate::{auth::WorkspaceRole, error::ApiResult};

#[derive(Debug, Clone)]
pub(in crate::storage::human_item_grants) struct GrantCandidate {
    pub id: String,
    pub root_file_id: String,
    pub role: WorkspaceRole,
    pub principal_kind: String,
    pub expires_at: Option<String>,
}

pub(in crate::storage::human_item_grants) fn whole_workspace_role_in_tx(
    tx: &Transaction<'_>,
    workspace_id: &str,
    email: &str,
) -> ApiResult<Option<WorkspaceRole>> {
    let role = tx
        .query_row(
            "SELECT role FROM (
                 SELECT wm.role AS role
                 FROM workspace_members wm
                 JOIN users u ON u.id = wm.user_id
                 WHERE wm.workspace_id = ?1 AND u.email = ?2
                   AND (wm.expires_at IS NULL OR julianday(wm.expires_at) > julianday('now'))
                 UNION ALL
                 SELECT wgg.role AS role
                 FROM workspace_group_grants wgg
                 JOIN group_members gm ON gm.group_id = wgg.group_id
                 JOIN users u ON u.id = gm.user_id
                 WHERE wgg.workspace_id = ?1 AND u.email = ?2
             )
             ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'editor' THEN 1 ELSE 2 END
             LIMIT 1",
            params![workspace_id, email],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(role.and_then(|value| WorkspaceRole::parse(&value)))
}

pub(super) fn actor_has_enabled_auth_account_in_tx(
    tx: &Transaction<'_>,
    email: &str,
) -> ApiResult<bool> {
    Ok(tx
        .query_row(
            "SELECT 1 FROM auth_accounts WHERE email = ?1 AND disabled_at IS NULL",
            [email],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub(in crate::storage::human_item_grants) fn matching_grants_at_root_in_tx(
    tx: &Transaction<'_>,
    root_file_id: &str,
    email: &str,
) -> ApiResult<Vec<GrantCandidate>> {
    let mut statement = tx.prepare(
        "SELECT g.id, g.root_file_id, g.role, g.principal_kind, g.expires_at
         FROM human_item_grants g
         WHERE g.root_file_id = ?1
           AND g.revoked_at IS NULL AND g.publication_pending = 0
           AND (g.expires_at IS NULL OR julianday(g.expires_at) > julianday('now'))
           AND (
             (g.principal_kind = 'account' AND EXISTS (
               SELECT 1 FROM users u
               JOIN auth_accounts accounts ON accounts.user_id = u.id
               WHERE u.id = g.principal_ref AND u.email = ?2
                 AND accounts.disabled_at IS NULL
             ))
             OR (g.principal_kind = 'group' AND EXISTS (
               SELECT 1 FROM group_members gm
               JOIN users u ON u.id = gm.user_id
               JOIN auth_accounts accounts ON accounts.user_id = u.id
               WHERE gm.group_id = g.principal_ref AND u.email = ?2
                 AND accounts.disabled_at IS NULL
             ))
             OR g.principal_kind = 'everyone'
           )
         ORDER BY g.created_at ASC, g.id ASC",
    )?;
    let rows = statement.query_map(params![root_file_id, email], |row| {
        let role: String = row.get(2)?;
        Ok(GrantCandidate {
            id: row.get(0)?,
            root_file_id: row.get(1)?,
            role: WorkspaceRole::parse(&role).ok_or_else(|| {
                rusqlite::Error::InvalidColumnType(
                    2,
                    "role".to_string(),
                    rusqlite::types::Type::Text,
                )
            })?,
            principal_kind: row.get(3)?,
            expires_at: row.get(4)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
