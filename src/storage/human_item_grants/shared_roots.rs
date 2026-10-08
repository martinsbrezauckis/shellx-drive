//! Canonical `Shared with me` root projection.
//!
//! Direct human grants and legacy whole-workspace memberships can both expose
//! the same canonical file. This module joins them by immutable
//! `workspace_id + file_id`, never by a display label, so a recipient sees one
//! virtual entry and no copied Drive entity.

use std::collections::HashSet;

use rusqlite::{params, OptionalExtension, Transaction};

use crate::{
    auth::{Actor, WorkspacePermission, WorkspaceRole},
    error::ApiResult,
    model::{DriveFile, SharedItemRoot},
};

use super::{
    super::{row_to_file, Storage},
    access::{
        live_ancestry_in_tx, matching_grants_at_root_in_tx, resolve_item_access_in_tx,
        retire_expired_grants_in_tx, role_rank, whole_workspace_role_in_tx, GrantCandidate,
    },
    capabilities::item_action_capabilities_in_tx,
    sync_roots::access_generation_in_tx,
};

pub(super) const MAX_SHARED_ROOTS: usize = 100;
pub(super) type SharedRootPage<T> = (Vec<T>, Option<(String, String)>);
const MAX_SHARED_WORKSPACES: usize = 1_000;
const SCAN_BATCH: usize = 100;
pub(super) const FILE_COLUMNS: &str = "f.id, f.workspace_id, f.parent_id, f.name, f.kind, f.revision, \
     f.trashed, f.starred, f.content_hash, f.created_at, f.updated_at, f.content_bytes, f.cover_hash";

impl Storage {
    /// Return one top-level virtual entry for every effective human or legacy
    /// whole-workspace share. Each response entry still points to the one
    /// canonical Drive file row and body.
    pub fn list_shared_item_roots_for_actor(
        &self,
        actor: &Actor,
        requested_limit: usize,
    ) -> ApiResult<Vec<SharedItemRoot>> {
        Ok(self
            .list_shared_item_roots_page_for_actor(actor, requested_limit, None)?
            .0)
    }

    pub fn list_shared_item_roots_page_for_actor(
        &self,
        actor: &Actor,
        requested_limit: usize,
        cursor: Option<&(String, String)>,
    ) -> ApiResult<SharedRootPage<SharedItemRoot>> {
        let limit = requested_limit.clamp(1, MAX_SHARED_ROOTS);
        let legacy_workspace_ids = legacy_workspace_ids(self, actor)?
            .into_iter()
            .collect::<HashSet<_>>();
        self.retire_expired_human_item_grants()?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        retire_expired_grants_in_tx(&tx)?;

        let mut roots: Vec<SharedItemRoot> = Vec::with_capacity(limit);
        let mut position = cursor.cloned();
        let mut next_cursor = None;
        loop {
            let files = candidate_files_in_tx(&tx, actor, position.as_ref())?;
            if files.is_empty() {
                break;
            }
            let count = files.len();
            for file in files {
                let candidate_position = (file.name.clone(), file.id.clone());
                let root = shared_root_in_tx(&tx, actor, &legacy_workspace_ids, file)?;
                if let Some(root) = root {
                    if roots.len() == limit {
                        // A scan position may name an unauthorized candidate.
                        // Bind the public cursor to a returned, revalidated root.
                        next_cursor = roots
                            .last()
                            .map(|root| (root.file.name.clone(), root.file.id.clone()));
                        break;
                    }
                    roots.push(root);
                }
                position = Some(candidate_position);
            }
            if next_cursor.is_some() || count < SCAN_BATCH {
                break;
            }
        }
        tx.commit()?;
        Ok((roots, next_cursor))
    }
}

fn legacy_workspace_ids(storage: &Storage, actor: &Actor) -> ApiResult<Vec<String>> {
    if actor.is_admin {
        return Ok(Vec::new());
    }
    Ok(storage
        .list_workspaces_for_actor_bounded(actor, MAX_SHARED_WORKSPACES)?
        .into_iter()
        .filter(|workspace| !workspace.archived)
        .filter(|workspace| matches!(workspace.role.as_deref(), Some("viewer" | "editor")))
        .map(|workspace| workspace.id)
        .collect())
}

fn candidate_files_in_tx(
    tx: &Transaction<'_>,
    actor: &Actor,
    cursor: Option<&(String, String)>,
) -> ApiResult<Vec<DriveFile>> {
    let mut statement = tx.prepare(&format!(
        "SELECT {FILE_COLUMNS} FROM files f
         WHERE f.trashed = 0
           AND (?2 IS NULL OR f.name > ?2 OR (f.name = ?2 AND f.id > ?3))
           AND (EXISTS (SELECT 1 FROM human_item_grants g
             WHERE g.root_file_id = f.id AND g.revoked_at IS NULL AND g.publication_pending = 0
             AND (g.expires_at IS NULL OR julianday(g.expires_at) > julianday('now'))
             AND (g.principal_kind = 'everyone'
             OR (g.principal_kind = 'account' AND EXISTS (
                SELECT 1 FROM users u JOIN auth_accounts accounts ON accounts.user_id = u.id
                WHERE u.id = g.principal_ref AND u.email = ?1 AND accounts.disabled_at IS NULL
             )) OR (g.principal_kind = 'group' AND EXISTS (
                SELECT 1 FROM group_members gm JOIN users u ON u.id = gm.user_id
                JOIN auth_accounts accounts ON accounts.user_id = u.id
                WHERE gm.group_id = g.principal_ref AND u.email = ?1 AND accounts.disabled_at IS NULL
             )))) OR (f.parent_id IS NULL AND EXISTS (
               SELECT 1 FROM workspace_members wm JOIN users u ON u.id = wm.user_id
               JOIN workspaces w ON w.id = wm.workspace_id
               WHERE wm.workspace_id = f.workspace_id AND wm.role IN ('viewer', 'editor')
                 AND (wm.expires_at IS NULL OR julianday(wm.expires_at) > julianday('now'))
                 AND u.email = ?1 AND w.archived_at IS NULL
             )))
         ORDER BY f.name ASC, f.id ASC LIMIT ?4"
    ))?;
    let files = statement
        .query_map(
            params![
                &actor.email,
                cursor.map(|v| &v.0),
                cursor.map(|v| &v.1),
                SCAN_BATCH as i64
            ],
            row_to_file,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(files)
}

fn shared_root_in_tx(
    tx: &Transaction<'_>,
    actor: &Actor,
    legacy_workspace_ids: &HashSet<String>,
    file: DriveFile,
) -> ApiResult<Option<SharedItemRoot>> {
    let workspace_role = whole_workspace_role_in_tx(tx, &file.workspace_id, &actor.email)?;
    if actor
        .allowed_workspace_ids
        .as_ref()
        .is_some_and(|ids| !ids.contains(&file.workspace_id))
        || workspace_role == Some(WorkspaceRole::Owner)
    {
        return Ok(None);
    }
    let has_legacy_membership =
        legacy_workspace_ids.contains(&file.workspace_id) && workspace_role.is_some();
    if has_legacy_membership && file.parent_id.is_none() {
        let role = workspace_role.expect("legacy membership has a role");
        let owner_label = owner_label_in_tx(tx, &file.workspace_id)?;
        let (_, action_capabilities) = item_action_capabilities_in_tx(tx, &file.id, actor)?;
        return Ok(Some(SharedItemRoot {
            root_file_id: file.id.clone(),
            workspace_id: file.workspace_id.clone(),
            sync_root_id: format!("workspace:{}", file.workspace_id),
            owner_label,
            role: role.as_db_str().to_string(),
            source: "workspace_membership".into(),
            inherited: false,
            grant_id: None,
            expires_at: None,
            access_generation: access_generation_in_tx(tx)?,
            action_capabilities,
            file,
        }));
    }
    // A whole-workspace membership already exposes descendants under its
    // canonical root; do not emit a second virtual entry for a nested grant.
    if has_legacy_membership || has_granted_ancestor(tx, &file, actor)? {
        return Ok(None);
    }
    let Some(grant) = preferred_direct_grant(tx, &file.id, &actor.email)? else {
        return Ok(None);
    };
    let access = resolve_item_access_in_tx(tx, &file.id, actor, WorkspacePermission::Read)?;
    let owner_label = owner_label_in_tx(tx, &file.workspace_id)?;
    let (_, action_capabilities) = item_action_capabilities_in_tx(tx, &file.id, actor)?;
    Ok(Some(SharedItemRoot {
        root_file_id: file.id.clone(),
        workspace_id: file.workspace_id.clone(),
        sync_root_id: format!("item-grant:{}", grant.id),
        owner_label,
        role: access.role,
        source: format!("human_{}", grant.principal_kind),
        inherited: false,
        grant_id: Some(grant.id),
        expires_at: grant.expires_at,
        access_generation: access_generation_in_tx(tx)?,
        action_capabilities,
        file,
    }))
}

fn has_granted_ancestor(tx: &Transaction<'_>, file: &DriveFile, actor: &Actor) -> ApiResult<bool> {
    for ancestor in live_ancestry_in_tx(tx, &file.id)?.iter().skip(1) {
        if !matching_grants_at_root_in_tx(tx, &ancestor.id, &actor.email)?.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn preferred_direct_grant(
    tx: &Transaction<'_>,
    file_id: &str,
    email: &str,
) -> ApiResult<Option<GrantCandidate>> {
    let mut grants = matching_grants_at_root_in_tx(tx, file_id, email)?;
    grants.sort_by(|left, right| {
        role_rank(right.role)
            .cmp(&role_rank(left.role))
            .then(left.id.cmp(&right.id))
    });
    Ok(grants.into_iter().next())
}

fn owner_label_in_tx(tx: &Transaction<'_>, workspace_id: &str) -> ApiResult<String> {
    Ok(tx
        .query_row(
            "SELECT accounts.email FROM account_private_workspaces private
             JOIN auth_accounts accounts ON accounts.user_id = private.user_id
             WHERE private.workspace_id = ?1",
            [workspace_id],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or_else(|| "Shared workspace".to_string()))
}
