//! SQL visibility predicates for account-wide metadata lists.
//!
//! Whole-workspace membership and a human item grant are deliberately kept as
//! separate sources of authority.  The latter walks *up* from the candidate
//! file to a matching granted root, so it can admit exactly that root and its
//! descendants without turning an item grant into workspace visibility.

use rusqlite::types::Value as SqlValue;

use crate::auth::Actor;

use super::super::actor_scope::actor_workspace_scope;
use super::super::MAX_FILE_TREE_DEPTH;

pub(in crate::storage) struct ActorFileVisibilityScope {
    pub cte_sql: String,
    pub parameters: Vec<SqlValue>,
    pub next_parameter: usize,
    item_email_parameter: Option<usize>,
    allowed_workspace_placeholders: Option<String>,
}

/// Build the account-wide file visibility relation used by search, recents,
/// starred, and activity.  A direct item grant is evaluated against each
/// candidate's bounded ancestry, so a matching grant cannot disclose a
/// sibling, parent, or workspace-level subject.
pub(in crate::storage) fn actor_file_visibility_scope(
    actor: &Actor,
) -> Option<ActorFileVisibilityScope> {
    let workspace_scope = actor_workspace_scope(actor)?;
    let mut parameters = workspace_scope.parameters;
    let mut next_parameter = workspace_scope.next_parameter;

    if actor.is_admin {
        return Some(ActorFileVisibilityScope {
            cte_sql: format!("visible_workspaces AS ({})", workspace_scope.sql),
            parameters,
            next_parameter,
            item_email_parameter: None,
            allowed_workspace_placeholders: None,
        });
    }

    let item_email_parameter = next_parameter;
    parameters.push(SqlValue::Text(actor.email.clone()));
    next_parameter += 1;
    let allowed_workspace_placeholders = actor.allowed_workspace_ids.as_ref().map(|ids| {
        let mut ids = ids.iter().collect::<Vec<_>>();
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
        parameters.extend(ids.into_iter().map(|id| SqlValue::Text(id.clone())));
        placeholders
    });

    Some(ActorFileVisibilityScope {
        cte_sql: format!("visible_workspaces AS ({})", workspace_scope.sql),
        parameters,
        next_parameter,
        item_email_parameter: Some(item_email_parameter),
        allowed_workspace_placeholders,
    })
}

impl ActorFileVisibilityScope {
    /// The alias is supplied only by static storage SQL (`files` or `f`), not
    /// from a request.  Effective role selection remains in
    /// `resolve_item_access_in_tx`, which terminally revalidates every
    /// published file against all current matching grants.
    pub(in crate::storage) fn visible_file_predicate(&self, file_alias: &str) -> String {
        let workspace_visible = format!(
            "EXISTS (SELECT 1 FROM visible_workspaces vw WHERE vw.id = {file_alias}.workspace_id)"
        );
        let Some(item_email_parameter) = self.item_email_parameter else {
            return workspace_visible;
        };
        let allowed_workspace = self
            .allowed_workspace_placeholders
            .as_deref()
            .map(|placeholders| format!(" AND {file_alias}.workspace_id IN ({placeholders})"))
            .unwrap_or_default();
        let item_visible = format!(
            "EXISTS (
                WITH RECURSIVE item_ancestors(id, workspace_id, parent_id, depth) AS (
                    SELECT {file_alias}.id, {file_alias}.workspace_id, {file_alias}.parent_id, 0
                    UNION ALL
                    SELECT parent.id, parent.workspace_id, parent.parent_id,
                           item_ancestors.depth + 1
                    FROM item_ancestors
                    JOIN files parent
                      ON parent.id = item_ancestors.parent_id
                     AND parent.workspace_id = item_ancestors.workspace_id
                    WHERE item_ancestors.depth < {MAX_FILE_TREE_DEPTH}
                )
                SELECT 1
                FROM item_ancestors ancestor
                JOIN human_item_grants grant
                  ON grant.root_file_id = ancestor.id
                 AND grant.workspace_id = {file_alias}.workspace_id
                WHERE grant.revoked_at IS NULL
                  AND grant.publication_pending = 0
                  AND (grant.expires_at IS NULL OR julianday(grant.expires_at) > julianday('now'))
                  AND EXISTS (
                    SELECT 1 FROM auth_accounts account
                    WHERE account.email = ?{item_email_parameter}
                      AND account.disabled_at IS NULL
                  )
                  AND EXISTS (
                    SELECT 1 FROM workspaces workspace
                    WHERE workspace.id = {file_alias}.workspace_id
                      AND workspace.archived_at IS NULL
                  )
                  {allowed_workspace}
                  AND (
                    grant.principal_kind = 'everyone'
                    OR (grant.principal_kind = 'account' AND EXISTS (
                      SELECT 1 FROM users user
                      JOIN auth_accounts account ON account.user_id = user.id
                      WHERE user.id = grant.principal_ref
                        AND user.email = ?{item_email_parameter}
                        AND account.disabled_at IS NULL
                    ))
                    OR (grant.principal_kind = 'group' AND EXISTS (
                      SELECT 1 FROM group_members member
                      JOIN users user ON user.id = member.user_id
                      JOIN auth_accounts account ON account.user_id = user.id
                      WHERE member.group_id = grant.principal_ref
                        AND user.email = ?{item_email_parameter}
                        AND account.disabled_at IS NULL
                    ))
                  )
            )"
        );
        format!("({workspace_visible} OR {item_visible})")
    }
}
