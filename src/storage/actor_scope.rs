use std::collections::HashSet;

use chrono::Utc;
use rusqlite::{
    params_from_iter,
    types::{Value as SqlValue, ValueRef},
};

use crate::{
    auth::Actor,
    error::{ApiError, ApiResult},
    model::Workspace,
};

use super::{Storage, MAX_WORKSPACE_NAME_BYTES};

pub(super) struct ActorWorkspaceScope {
    pub sql: String,
    pub parameters: Vec<SqlValue>,
    pub next_parameter: usize,
}

/// Build the shared actor-visible workspace relation used by account-wide
/// storage queries. Keeping authorization in one CTE prevents compatibility
/// endpoints from drifting back to global collection plus post-filtering.
pub(super) fn actor_workspace_scope(actor: &Actor) -> Option<ActorWorkspaceScope> {
    if actor
        .allowed_workspace_ids
        .as_ref()
        .is_some_and(HashSet::is_empty)
    {
        return None;
    }

    let mut parameters = vec![SqlValue::Text(actor.email.clone())];
    let mut next_parameter = 2usize;
    let mut sql = if actor.is_admin {
        "SELECT w.id, w.name,
                CASE WHEN EXISTS (
                  SELECT 1
                  FROM workspace_members wm
                  JOIN users u ON u.id = wm.user_id
                  WHERE wm.workspace_id = w.id
                    AND u.email = ?1
                    AND wm.role = 'owner'
                ) THEN 'owner' ELSE 'admin' END AS access_role
         FROM workspaces w
         WHERE w.archived_at IS NULL"
            .to_string()
    } else {
        parameters.push(SqlValue::Text(Utc::now().to_rfc3339()));
        next_parameter = 3;
        "SELECT w.id, w.name,
                CASE
                  WHEN EXISTS (
                    SELECT 1
                    FROM workspace_members wm
                    JOIN users u ON u.id = wm.user_id
                    WHERE wm.workspace_id = w.id
                      AND u.email = ?1
                      AND wm.role = 'owner'
                      AND (wm.expires_at IS NULL OR wm.expires_at > ?2)
                  ) THEN 'owner'
                  WHEN EXISTS (
                    SELECT 1
                    FROM workspace_members wm
                    JOIN users u ON u.id = wm.user_id
                    WHERE wm.workspace_id = w.id
                      AND u.email = ?1
                      AND wm.role = 'editor'
                      AND (wm.expires_at IS NULL OR wm.expires_at > ?2)
                  ) OR EXISTS (
                    SELECT 1
                    FROM workspace_group_grants wgg
                    JOIN group_members gm ON gm.group_id = wgg.group_id
                    JOIN users u ON u.id = gm.user_id
                    WHERE wgg.workspace_id = w.id
                      AND u.email = ?1
                      AND wgg.role = 'editor'
                  ) THEN 'editor'
                  ELSE 'viewer'
                END AS access_role
         FROM workspaces w
         WHERE w.archived_at IS NULL
           AND (
             EXISTS (
               SELECT 1
               FROM workspace_members wm
               JOIN users u ON u.id = wm.user_id
               WHERE wm.workspace_id = w.id
                 AND u.email = ?1
                 AND (wm.expires_at IS NULL OR wm.expires_at > ?2)
             ) OR EXISTS (
               SELECT 1
               FROM workspace_group_grants wgg
               JOIN group_members gm ON gm.group_id = wgg.group_id
               JOIN users u ON u.id = gm.user_id
               WHERE wgg.workspace_id = w.id AND u.email = ?1
             )
           )"
        .to_string()
    };

    if let Some(allowed_workspace_ids) = actor.allowed_workspace_ids.as_ref() {
        let mut ids = allowed_workspace_ids.iter().collect::<Vec<_>>();
        ids.sort_unstable();
        let placeholders = ids
            .iter()
            .map(|_| {
                let placeholder = format!("?{next_parameter}");
                next_parameter += 1;
                placeholder
            })
            .collect::<Vec<_>>()
            .join(", ");
        sql.push_str(&format!(" AND w.id IN ({placeholders})"));
        parameters.extend(ids.into_iter().map(|id| SqlValue::Text(id.clone())));
    }

    Some(ActorWorkspaceScope {
        sql,
        parameters,
        next_parameter,
    })
}

impl Storage {
    /// Select at most `max_rows` visible workspaces, with one sentinel row to
    /// reject an oversized account before a caller can fan out into per-
    /// workspace metadata work. This is intentionally separate from the
    /// legacy unbounded listing API so existing callers retain their contract.
    pub(crate) fn list_workspaces_for_actor_bounded(
        &self,
        actor: &Actor,
        max_rows: usize,
    ) -> ApiResult<Vec<Workspace>> {
        let sentinel_limit = i64::try_from(max_rows.checked_add(1).ok_or_else(|| {
            ApiError::PayloadTooLarge("workspace selection overflow".to_string())
        })?)
        .map_err(|_| ApiError::PayloadTooLarge("workspace selection overflow".to_string()))?;
        let mut workspaces = if actor.is_admin {
            self.list_workspaces_bounded(sentinel_limit)?
        } else {
            let Some(scope) = actor_workspace_scope(actor) else {
                return Ok(Vec::new());
            };
            let limit_parameter = scope.next_parameter;
            let mut parameters = scope.parameters;
            parameters.push(SqlValue::Integer(sentinel_limit));
            let sql = format!(
                "WITH visible_workspaces AS ({})
                 SELECT w.id, w.name, w.storage_mode, w.created_at,
                        COALESCE(w.updated_at, w.created_at), w.archived_at,
                        w.tenant_id, visible_workspaces.access_role
                 FROM workspaces w
                 JOIN visible_workspaces ON visible_workspaces.id = w.id
                 ORDER BY w.name ASC, w.id ASC
                 LIMIT ?{limit_parameter}",
                scope.sql
            );
            let conn = self.conn.lock().unwrap();
            let _read_snapshot = conn.unchecked_transaction()?;
            // This reader also feeds shared-root discovery for workspaces
            // with no file candidates. Reject their labels before sorting.
            let unsafe_workspace_name: bool = conn.query_row(
                &format!(
                    "WITH visible_workspaces AS ({})
                    SELECT EXISTS (SELECT 1 FROM visible_workspaces
                    WHERE length(CAST(name AS BLOB)) > {MAX_WORKSPACE_NAME_BYTES})",
                    scope.sql
                ),
                params_from_iter(parameters[..parameters.len() - 1].iter()),
                |row| row.get(0),
            )?;
            if unsafe_workspace_name {
                return Err(ApiError::PayloadTooLarge(
                    "workspace name exceeds 255 bytes; rename it before browsing".to_string(),
                ));
            }
            let mut statement = conn.prepare(&sql)?;
            let mut rows = statement.query(params_from_iter(parameters.iter()))?;
            let mut workspaces = Vec::new();
            while let Some(row) = rows.next()? {
                if let ValueRef::Text(name) = row.get_ref(1)? {
                    if name.len() > MAX_WORKSPACE_NAME_BYTES {
                        return Err(ApiError::PayloadTooLarge(
                            "workspace name exceeds 255 bytes; rename it before browsing"
                                .to_string(),
                        ));
                    }
                }
                let archived_at: Option<String> = row.get(5)?;
                workspaces.push(Workspace {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    storage_mode: row.get(2)?,
                    created_at: row.get(3)?,
                    updated_at: row.get(4)?,
                    archived: archived_at.is_some(),
                    archived_at,
                    tenant_id: row.get(6)?,
                    role: Some(row.get(7)?),
                });
            }
            workspaces
        };
        if workspaces.len() > max_rows {
            return Err(ApiError::PayloadTooLarge(format!(
                "workspace metadata selection exceeds the {max_rows}-workspace limit"
            )));
        }
        // The scoped query's order is already deterministic; keep the same
        // name sort as the legacy API and preserve the admin path's contract.
        workspaces.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(workspaces)
    }
}
