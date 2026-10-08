use std::collections::BTreeMap;

use rusqlite::{params, OptionalExtension, Transaction};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission, WorkspaceRole},
    error::{ApiError, ApiResult},
    model::{DriveFile, SyncRoot},
};

use super::{
    super::{authorization, Storage, MAX_FILE_TREE_NODES},
    access::{
        live_ancestry_in_tx, matching_grants_at_root_in_tx, resolve_item_access_in_tx, role_rank,
        whole_workspace_role_in_tx,
    },
    capabilities::{item_action_capabilities_in_tx, workspace_action_capabilities_in_tx},
};

mod page;
mod paging;
mod revalidate;

use paging::next_grant_page_in_tx;

impl Storage {
    // Root reads use live expiry predicates in workspace membership and grant
    // resolution. Retention is a mutation-path task, never a global sweep under
    // a reader's storage lock.
    pub fn list_sync_roots_for_actor(&self, actor: &Actor) -> ApiResult<Vec<SyncRoot>> {
        let actor = sync_actor(actor);
        let workspaces = self
            .list_workspaces_for_actor_bounded(&actor, 1_000)
            .map_err(|error| match error {
                ApiError::PayloadTooLarge(_) => ApiError::SyncRootDiscoveryOverflow,
                other => other,
            })?;
        let mut roots = workspaces
            .into_iter()
            .map(|workspace| SyncRoot {
                id: format!("workspace:{}", workspace.id),
                kind: "workspace".to_string(),
                workspace_id: workspace.id,
                root_file_id: None,
                grant_id: None,
                owner_label: String::new(),
                role: workspace.role.unwrap_or_else(|| "viewer".to_string()),
                expires_at: None,
                label: workspace.name,
                access_generation: 0,
                action_capabilities: Default::default(),
            })
            .collect::<Vec<_>>();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let generation = access_generation_in_tx(&tx)?;
        for root in &mut roots {
            root.owner_label = workspace_owner_label_in_tx(&tx, &root.workspace_id)?;
            root.access_generation = generation;
            root.action_capabilities =
                workspace_action_capabilities_in_tx(&tx, &root.workspace_id, &actor)?;
        }
        roots.extend(item_sync_roots_in_tx(&tx, &actor)?);
        tx.commit()?;
        roots.sort_by(|left, right| left.label.cmp(&right.label).then(left.id.cmp(&right.id)));
        Ok(roots)
    }

    pub fn sync_root_manifest(
        &self,
        root_id: &str,
        actor: &Actor,
        expected_access_generation: u64,
    ) -> ApiResult<(SyncRoot, Vec<DriveFile>, i64)> {
        let root = self.resolve_sync_root(root_id, &sync_actor(actor))?;
        ensure_matching_access_generation(root.access_generation, expected_access_generation)?;
        let (files, next_cursor) =
            super::super::sync::manifest_with_cursor(self, &root.workspace_id, || {
                if let Some(file_id) = root.root_file_id.as_deref() {
                    self.active_descendants_inclusive_bounded(file_id)
                } else {
                    self.list_sync_manifest_files(&root.workspace_id, MAX_FILE_TREE_NODES)
                }
            })?;
        Ok((root, files, next_cursor))
    }

    pub fn ensure_sync_root_publication_authorized(
        &self,
        root_id: &str,
        actor: &Actor,
        credential: &DriveCredential,
    ) -> ApiResult<SyncRoot> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        authorization::ensure_source_credential_active(&tx, actor, credential)?;
        let root = resolve_sync_root_in_tx(&tx, root_id, &sync_actor(actor))?;
        tx.commit()?;
        Ok(root)
    }

    pub fn revalidate_sync_roots_publication_authorized(
        &self,
        root_ids: &[String],
        actor: &Actor,
        credential: &DriveCredential,
    ) -> ApiResult<Vec<SyncRoot>> {
        revalidate::ensure_full_root_publication_limit(root_ids.len())?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        authorization::ensure_source_credential_active(&tx, actor, credential)?;
        let actor = sync_actor(actor);
        let mut roots = Vec::with_capacity(root_ids.len());
        for root_id in root_ids {
            roots.push(resolve_sync_root_in_tx(&tx, root_id, &actor)?);
        }
        tx.commit()?;
        Ok(roots)
    }

    pub fn ensure_sync_root_manifest_publication_authorized(
        &self,
        root_id: &str,
        files: &[DriveFile],
        actor: &Actor,
        credential: &DriveCredential,
        expected_access_generation: u64,
    ) -> ApiResult<SyncRoot> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        authorization::ensure_source_credential_active(&tx, actor, credential)?;
        let actor = sync_actor(actor);
        let root = resolve_sync_root_in_tx(&tx, root_id, &actor)?;
        ensure_matching_access_generation(root.access_generation, expected_access_generation)?;
        for file in files {
            let ancestry = live_ancestry_in_tx(&tx, &file.id)?;
            if ancestry
                .first()
                .is_none_or(|current| current.workspace_id != root.workspace_id)
            {
                return Err(ApiError::NotFound);
            }
            if let Some(root_file_id) = root.root_file_id.as_deref() {
                if !ancestry.iter().any(|ancestor| ancestor.id == root_file_id) {
                    return Err(ApiError::NotFound);
                }
            }
            resolve_item_access_in_tx(&tx, &file.id, &actor, WorkspacePermission::Read)?;
        }
        tx.commit()?;
        Ok(root)
    }

    fn resolve_sync_root(&self, root_id: &str, actor: &Actor) -> ApiResult<SyncRoot> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let root = resolve_sync_root_in_tx(&tx, root_id, actor)?;
        tx.commit()?;
        Ok(root)
    }
}

pub(super) fn resolve_sync_root_in_tx(
    tx: &Transaction<'_>,
    root_id: &str,
    actor: &Actor,
) -> ApiResult<SyncRoot> {
    if let Some(workspace_id) = root_id.strip_prefix("workspace:") {
        if workspace_id.is_empty()
            || actor
                .allowed_workspace_ids
                .as_ref()
                .is_some_and(|ids| !ids.contains(workspace_id))
        {
            return Err(ApiError::NotFound);
        }
        let role = whole_workspace_role_in_tx(tx, workspace_id, &actor.email)?
            .ok_or(ApiError::NotFound)?;
        let label: String = tx
            .query_row(
                "SELECT name FROM workspaces WHERE id = ?1 AND archived_at IS NULL",
                [workspace_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        return Ok(SyncRoot {
            id: root_id.to_string(),
            kind: "workspace".to_string(),
            workspace_id: workspace_id.to_string(),
            root_file_id: None,
            grant_id: None,
            owner_label: workspace_owner_label_in_tx(tx, workspace_id)?,
            role: role.as_db_str().to_string(),
            expires_at: None,
            label,
            access_generation: access_generation_in_tx(tx)?,
            action_capabilities: workspace_action_capabilities_in_tx(tx, workspace_id, actor)?,
        });
    }
    let grant_id = root_id
        .strip_prefix("item-grant:")
        .ok_or(ApiError::NotFound)?;
    let root = item_sync_root_by_grant_in_tx(tx, grant_id, actor)?.ok_or(ApiError::NotFound)?;
    resolve_item_access_in_tx(
        tx,
        root.root_file_id.as_deref().ok_or(ApiError::NotFound)?,
        actor,
        WorkspacePermission::Read,
    )?;
    Ok(root)
}

fn workspace_owner_label_in_tx(tx: &Transaction<'_>, workspace_id: &str) -> ApiResult<String> {
    Ok(tx.query_row("SELECT accounts.email FROM account_private_workspaces private JOIN auth_accounts accounts ON accounts.user_id = private.user_id WHERE private.workspace_id = ?1", [workspace_id], |row| row.get(0)).optional()?.unwrap_or_else(|| "Shared workspace".to_string()))
}

fn item_sync_roots_in_tx(tx: &Transaction<'_>, actor: &Actor) -> ApiResult<Vec<SyncRoot>> {
    let mut canonical = BTreeMap::<String, CanonicalSyncRoot>::new();
    let mut after_file_id: Option<String> = None;
    let mut after_grant_id: Option<String> = None;
    loop {
        let page = next_grant_page_in_tx(
            tx,
            &actor.email,
            after_file_id.as_deref(),
            after_grant_id.as_deref(),
        )?;
        if page.is_empty() {
            break;
        }
        for (_grant_id, workspace_id, file_id, role) in &page {
            if actor
                .allowed_workspace_ids
                .as_ref()
                .is_some_and(|ids| !ids.contains(workspace_id))
                || whole_workspace_role_in_tx(tx, workspace_id, &actor.email)?.is_some()
            {
                continue;
            }
            let ancestry = live_ancestry_in_tx(tx, file_id)?;
            let mut top = None;
            for ancestor in ancestry.iter().rev() {
                let grants = matching_grants_at_root_in_tx(tx, &ancestor.id, &actor.email)?;
                if !grants.is_empty() {
                    top = Some((ancestor.id.clone(), grants));
                    break;
                }
            }
            let Some((root_file_id, mut grants)) = top else {
                continue;
            };
            grants.sort_by(|left, right| left.id.cmp(&right.id));
            let stable = grants.first().ok_or(ApiError::NotFound)?;
            let role = grants
                .iter()
                .map(|grant| grant.role)
                .chain(std::iter::once(
                    WorkspaceRole::parse(role).ok_or(ApiError::NotFound)?,
                ))
                .max_by_key(|role| role_rank(*role))
                .ok_or(ApiError::NotFound)?;
            let label: String = tx.query_row(
                "SELECT name FROM files WHERE id = ?1",
                [&root_file_id],
                |row| row.get(0),
            )?;
            let entry =
                canonical
                    .entry(root_file_id.clone())
                    .or_insert_with(|| CanonicalSyncRoot {
                        grant_id: stable.id.clone(),
                        workspace_id: workspace_id.clone(),
                        root_file_id,
                        role,
                        expires_at: stable.expires_at.clone(),
                        label,
                    });
            if role_rank(role) > role_rank(entry.role) {
                entry.role = role;
            }
        }
        let (grant_id, _, file_id, _) = page.last().ok_or(ApiError::NotFound)?;
        after_file_id = Some(file_id.clone());
        after_grant_id = Some(grant_id.clone());
    }
    canonical
        .into_values()
        .map(|root| {
            let action_capabilities =
                item_action_capabilities_in_tx(tx, &root.root_file_id, actor)?.1;
            Ok(SyncRoot {
                id: format!("item-grant:{}", root.grant_id),
                kind: "item_grant".to_string(),
                workspace_id: root.workspace_id.clone(),
                root_file_id: Some(root.root_file_id),
                grant_id: Some(root.grant_id),
                owner_label: workspace_owner_label_in_tx(tx, &root.workspace_id)?,
                role: root.role.as_db_str().to_string(),
                expires_at: root.expires_at,
                label: root.label,
                access_generation: access_generation_in_tx(tx)?,
                action_capabilities,
            })
        })
        .collect()
}

fn item_sync_root_by_grant_in_tx(
    tx: &Transaction<'_>,
    grant_id: &str,
    actor: &Actor,
) -> ApiResult<Option<SyncRoot>> {
    let row = tx.query_row(
        "SELECT g.workspace_id, g.root_file_id, g.expires_at, f.name FROM human_item_grants g JOIN files f ON f.id = g.root_file_id WHERE g.id = ?1 AND g.revoked_at IS NULL AND g.publication_pending = 0 AND f.trashed = 0 AND EXISTS (SELECT 1 FROM auth_accounts a WHERE a.email = ?2 AND a.disabled_at IS NULL) AND (g.expires_at IS NULL OR julianday(g.expires_at) > julianday('now')) AND (g.principal_kind = 'everyone' OR (g.principal_kind = 'account' AND EXISTS (SELECT 1 FROM users u JOIN auth_accounts a ON a.user_id = u.id WHERE u.id = g.principal_ref AND u.email = ?2 AND a.disabled_at IS NULL)) OR (g.principal_kind = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN users u ON u.id = gm.user_id JOIN auth_accounts a ON a.user_id = u.id WHERE gm.group_id = g.principal_ref AND u.email = ?2 AND a.disabled_at IS NULL)))",
        params![grant_id, &actor.email], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, String>(3)?)),
    ).optional()?;
    let Some((workspace_id, file_id, expires_at, label)) = row else {
        return Ok(None);
    };
    if whole_workspace_role_in_tx(tx, &workspace_id, &actor.email)?.is_some() {
        return Ok(None);
    }
    let grants = matching_grants_at_root_in_tx(tx, &file_id, &actor.email)?;
    let role = grants
        .iter()
        .map(|grant| grant.role)
        .max_by_key(|role| role_rank(*role))
        .ok_or(ApiError::NotFound)?;
    let action_capabilities = item_action_capabilities_in_tx(tx, &file_id, actor)?.1;
    Ok(Some(SyncRoot {
        id: format!("item-grant:{grant_id}"),
        kind: "item_grant".to_string(),
        workspace_id: workspace_id.clone(),
        root_file_id: Some(file_id),
        grant_id: Some(grant_id.to_string()),
        owner_label: workspace_owner_label_in_tx(tx, &workspace_id)?,
        role: role.as_db_str().to_string(),
        expires_at,
        label,
        access_generation: access_generation_in_tx(tx)?,
        action_capabilities,
    }))
}

pub(super) fn access_generation_in_tx(tx: &Transaction<'_>) -> ApiResult<u64> {
    let generation: i64 = tx.query_row(
        "SELECT generation FROM human_item_access_generation WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    u64::try_from(generation).map_err(|_| ApiError::NotFound)
}

fn ensure_matching_access_generation(actual: u64, expected: u64) -> ApiResult<()> {
    if expected == 0 {
        return Err(ApiError::Validation(
            "sync root access generation must be positive".to_string(),
        ));
    }
    if actual != expected {
        return Err(ApiError::PreconditionFailed);
    }
    Ok(())
}

struct CanonicalSyncRoot {
    grant_id: String,
    workspace_id: String,
    root_file_id: String,
    role: WorkspaceRole,
    expires_at: Option<String>,
    label: String,
}

fn sync_actor(actor: &Actor) -> Actor {
    Actor {
        is_admin: false,
        ..actor.clone()
    }
}
