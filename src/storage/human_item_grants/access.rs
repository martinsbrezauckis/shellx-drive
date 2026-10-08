use std::collections::HashSet;

use rusqlite::{OptionalExtension, Transaction};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission, WorkspaceRole},
    error::{ApiError, ApiResult},
    model::EffectiveItemAccess,
};

use super::super::{authorization, Storage, MAX_COMPATIBILITY_FILE_LIST, MAX_FILE_TREE_DEPTH};
pub(super) use super::retention::retire_expired_grants_in_tx;

mod queries;

use queries::actor_has_enabled_auth_account_in_tx;
pub(super) use queries::{
    matching_grants_at_root_in_tx, whole_workspace_role_in_tx, GrantCandidate,
};

#[derive(Debug, Clone)]
pub(super) struct Ancestor {
    pub(super) id: String,
    pub(super) workspace_id: String,
    parent_id: Option<String>,
}

pub(in crate::storage) fn resolve_item_access_in_tx(
    tx: &Transaction<'_>,
    file_id: &str,
    actor: &Actor,
    permission: WorkspacePermission,
) -> ApiResult<EffectiveItemAccess> {
    let ancestry = live_ancestry_in_tx(tx, file_id)?;
    let workspace_id = ancestry
        .first()
        .map(|file| file.workspace_id.clone())
        .ok_or(ApiError::NotFound)?;
    if actor
        .allowed_workspace_ids
        .as_ref()
        .is_some_and(|ids| !ids.contains(&workspace_id))
    {
        return Err(ApiError::Forbidden);
    }
    let workspace_live = tx
        .query_row(
            "SELECT CASE WHEN archived_at IS NULL THEN 1 ELSE 0 END FROM workspaces WHERE id = ?1",
            [&workspace_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0)
        != 0;
    if !workspace_live {
        return Err(ApiError::NotFound);
    }
    if actor.is_admin {
        return Ok(EffectiveItemAccess {
            workspace_id,
            root_file_id: file_id.to_string(),
            role: "owner".to_string(),
            source: "administrator".to_string(),
            inherited: false,
            grant_id: None,
        });
    }
    if let Some(role) = whole_workspace_role_in_tx(tx, &workspace_id, &actor.email)? {
        if role.allows(permission) {
            return Ok(EffectiveItemAccess {
                workspace_id,
                root_file_id: file_id.to_string(),
                role: role.as_db_str().to_string(),
                source: "workspace_membership".to_string(),
                inherited: false,
                grant_id: None,
            });
        }
    }
    if !actor_has_enabled_auth_account_in_tx(tx, &actor.email)? {
        return Err(ApiError::Forbidden);
    }

    let mut chosen: Option<(GrantCandidate, usize)> = None;
    for (distance, ancestor) in ancestry.iter().enumerate() {
        for candidate in matching_grants_at_root_in_tx(tx, &ancestor.id, &actor.email)? {
            let replace = chosen.as_ref().is_none_or(|(current, current_distance)| {
                role_rank(candidate.role) > role_rank(current.role)
                    || (candidate.role == current.role && distance < *current_distance)
            });
            if replace {
                chosen = Some((candidate, distance));
            }
        }
    }
    let Some((candidate, distance)) = chosen else {
        return Err(ApiError::Forbidden);
    };
    if !candidate.role.allows(permission) {
        return Err(ApiError::Forbidden);
    }
    Ok(EffectiveItemAccess {
        workspace_id,
        root_file_id: candidate.root_file_id,
        role: candidate.role.as_db_str().to_string(),
        source: format!("human_{}", candidate.principal_kind),
        inherited: distance != 0,
        grant_id: Some(candidate.id),
    })
}

/// Normalize an item response while the authorization transaction is still
/// open. A readable item can report a denied write or manage operation, but
/// an unreadable item must have the same response as an absent item.
pub(in crate::storage) fn resolve_item_response_access_in_tx(
    tx: &Transaction<'_>,
    file_id: &str,
    actor: &Actor,
    permission: WorkspacePermission,
) -> ApiResult<EffectiveItemAccess> {
    match resolve_item_access_in_tx(tx, file_id, actor, permission) {
        Err(ApiError::Forbidden) => {
            if matches!(permission, WorkspacePermission::Read) {
                return Err(ApiError::NotFound);
            }
            match resolve_item_access_in_tx(tx, file_id, actor, WorkspacePermission::Read) {
                Ok(_) => Err(ApiError::Forbidden),
                Err(ApiError::Forbidden | ApiError::NotFound) => Err(ApiError::NotFound),
                Err(error) => Err(error),
            }
        }
        result => result,
    }
}

/// Recheck both the bearer/session and current item authority in the same
/// transaction that is about to publish a mutation or response.  This keeps
/// item grants from being accidentally widened by legacy operations which
/// only know about a workspace id.
pub(in crate::storage) fn ensure_item_authorized_in_tx(
    tx: &Transaction<'_>,
    file_id: &str,
    actor: &Actor,
    source_credential: &DriveCredential,
    permission: WorkspacePermission,
) -> ApiResult<EffectiveItemAccess> {
    authorization::ensure_source_credential_active(tx, actor, source_credential)?;
    resolve_item_access_in_tx(tx, file_id, actor, permission)
}

/// A create/copy/move destination has no file id of its own yet.  A scoped
/// editor can target only a live parent inside the granted closure.  Creating
/// at a workspace root remains a whole-workspace operation.
pub(in crate::storage) fn ensure_item_destination_authorized_in_tx(
    tx: &Transaction<'_>,
    workspace_id: &str,
    parent_id: Option<&str>,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    match parent_id {
        Some(parent_id) => {
            authorization::ensure_source_credential_active(tx, actor, source_credential)?;
            let access = resolve_item_response_access_in_tx(
                tx,
                parent_id,
                actor,
                WorkspacePermission::Write,
            )?;
            if access.workspace_id == workspace_id {
                Ok(())
            } else {
                Err(ApiError::NotFound)
            }
        }
        None => authorization::ensure_workspace_authorized(
            tx,
            workspace_id,
            actor,
            source_credential,
            WorkspacePermission::Write,
        ),
    }
}

pub(super) fn role_rank(role: WorkspaceRole) -> u8 {
    match role {
        WorkspaceRole::Viewer => 0,
        WorkspaceRole::Editor => 1,
        WorkspaceRole::Owner => 2,
    }
}

pub(super) fn live_ancestry_in_tx(tx: &Transaction<'_>, file_id: &str) -> ApiResult<Vec<Ancestor>> {
    let mut current = Some(file_id.to_string());
    let mut seen = HashSet::new();
    let mut ancestry = Vec::new();
    for _ in 0..=MAX_FILE_TREE_DEPTH {
        let Some(id) = current.take() else {
            return Ok(ancestry);
        };
        if !seen.insert(id.clone()) {
            return Err(ApiError::NotFound);
        }
        let ancestor = tx
            .query_row(
                "SELECT id, workspace_id, parent_id, trashed FROM files WHERE id = ?1",
                [&id],
                |row| {
                    let trashed: i64 = row.get(3)?;
                    Ok((
                        Ancestor {
                            id: row.get(0)?,
                            workspace_id: row.get(1)?,
                            parent_id: row.get(2)?,
                        },
                        trashed,
                    ))
                },
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        if ancestor.1 != 0
            || ancestry
                .first()
                .is_some_and(|child: &Ancestor| child.workspace_id != ancestor.0.workspace_id)
        {
            return Err(ApiError::NotFound);
        }
        current = ancestor.0.parent_id.clone();
        ancestry.push(ancestor.0);
    }
    Err(ApiError::NotFound)
}

impl Storage {
    pub(super) fn retire_expired_human_item_grants(&self) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        retire_expired_grants_in_tx(&tx)?;
        tx.commit()?;
        Ok(())
    }

    pub fn ensure_item_permission(
        &self,
        file_id: &str,
        actor: &Actor,
        permission: WorkspacePermission,
    ) -> ApiResult<EffectiveItemAccess> {
        self.retire_expired_human_item_grants()?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        retire_expired_grants_in_tx(&tx)?;
        let access = resolve_item_access_in_tx(&tx, file_id, actor, permission)?;
        tx.commit()?;
        Ok(access)
    }

    /// File IDs are opaque to a caller without read access. Keep a missing
    /// item and an existing but unreadable item indistinguishable at routes;
    /// callers that can read an item still receive Forbidden for a denied
    /// write or manage operation.
    pub fn ensure_item_response_permission(
        &self,
        file_id: &str,
        actor: &Actor,
        permission: WorkspacePermission,
    ) -> ApiResult<EffectiveItemAccess> {
        match self.ensure_item_permission(file_id, actor, permission) {
            Err(ApiError::Forbidden) => Err(self.item_response_denial(file_id, actor, permission)),
            result => result,
        }
    }

    fn item_response_denial(
        &self,
        file_id: &str,
        actor: &Actor,
        permission: WorkspacePermission,
    ) -> ApiError {
        if matches!(permission, WorkspacePermission::Read) {
            return ApiError::NotFound;
        }
        match self.ensure_item_permission(file_id, actor, WorkspacePermission::Read) {
            Ok(_) => ApiError::Forbidden,
            Err(ApiError::Forbidden | ApiError::NotFound) => ApiError::NotFound,
            Err(error) => error,
        }
    }

    pub fn ensure_item_publication_authorized(
        &self,
        file_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
        permission: WorkspacePermission,
    ) -> ApiResult<EffectiveItemAccess> {
        self.retire_expired_human_item_grants()?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        retire_expired_grants_in_tx(&tx)?;
        authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
        let access = resolve_item_access_in_tx(&tx, file_id, actor, permission)?;
        tx.commit()?;
        Ok(access)
    }

    pub fn ensure_item_response_publication_authorized(
        &self,
        file_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
        permission: WorkspacePermission,
    ) -> ApiResult<EffectiveItemAccess> {
        match self.ensure_item_publication_authorized(file_id, actor, source_credential, permission)
        {
            Err(ApiError::Forbidden) => Err(self.item_response_denial(file_id, actor, permission)),
            result => result,
        }
    }

    /// Revalidate one bounded metadata page in a single transaction just
    /// before it is published. This prevents a legacy list response from
    /// being widened between independent per-row terminal checks.
    pub(crate) fn ensure_items_publication_authorized(
        &self,
        file_ids: &[String],
        actor: &Actor,
        source_credential: &DriveCredential,
        permission: WorkspacePermission,
    ) -> ApiResult<()> {
        if file_ids.len() > MAX_COMPATIBILITY_FILE_LIST {
            return Err(ApiError::PayloadTooLarge(format!(
                "item metadata publication selects more than {MAX_COMPATIBILITY_FILE_LIST} subjects"
            )));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
        for file_id in file_ids {
            resolve_item_access_in_tx(&tx, file_id, actor, permission)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Revalidate a compatibility file page without making Trash unusable.
    /// Live rows retain item-grant authorization. A row selected as directly
    /// trashed is never available through an item grant, so its metadata may
    /// be published only while the actor still has workspace-wide read access.
    /// The selected workspace and trash state must still match in the same
    /// transaction as the credential check.
    pub(crate) fn ensure_file_metadata_publication_authorized(
        &self,
        files: &[(String, String, bool)],
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        if files.len() > MAX_COMPATIBILITY_FILE_LIST {
            return Err(ApiError::PayloadTooLarge(format!(
                "file metadata publication selects more than {MAX_COMPATIBILITY_FILE_LIST} subjects"
            )));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
        let mut seen = HashSet::new();
        for (file_id, selected_workspace_id, selected_trashed) in files {
            if !seen.insert(file_id) {
                continue;
            }
            let (workspace_id, trashed) = tx
                .query_row(
                    "SELECT workspace_id, trashed FROM files WHERE id = ?1",
                    [file_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0)),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if workspace_id != *selected_workspace_id || trashed != *selected_trashed {
                return Err(ApiError::NotFound);
            }
            if trashed {
                authorization::ensure_workspace_authorized(
                    &tx,
                    &workspace_id,
                    actor,
                    source_credential,
                    WorkspacePermission::Read,
                )?;
            } else {
                let access =
                    resolve_item_access_in_tx(&tx, file_id, actor, WorkspacePermission::Read)?;
                if access.workspace_id != workspace_id {
                    return Err(ApiError::NotFound);
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
}
