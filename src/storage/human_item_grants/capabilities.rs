use rusqlite::Transaction;

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission, WorkspaceRole},
    error::{ApiError, ApiResult},
    model::ItemActionCapabilities,
};

use super::{
    super::{authorization, Storage},
    access::{
        resolve_item_access_in_tx, resolve_item_response_access_in_tx, retire_expired_grants_in_tx,
        whole_workspace_role_in_tx,
    },
    sync_roots::access_generation_in_tx,
};

impl Storage {
    /// Return the current item-management affordances only after proving that
    /// the caller can read the canonical item.  Scoped human editors are
    /// intentionally never promoted into any delegation authority here.
    pub fn item_action_capabilities(
        &self,
        file_id: &str,
        actor: &Actor,
    ) -> ApiResult<(String, ItemActionCapabilities, u64)> {
        self.retire_expired_human_item_grants()?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        retire_expired_grants_in_tx(&tx)?;
        let (workspace_id, capabilities) = item_action_capabilities_in_tx(&tx, file_id, actor)?;
        let access_generation = access_generation_in_tx(&tx)?;
        tx.commit()?;
        Ok((workspace_id, capabilities, access_generation))
    }

    /// Recalculate the projection in the same terminal transaction as source
    /// credential validation.  A stale read must not publish old buttons after
    /// a membership or account-state change.
    pub fn item_action_capabilities_publication_authorized(
        &self,
        file_id: &str,
        actor: &Actor,
        credential: &DriveCredential,
        permission: WorkspacePermission,
    ) -> ApiResult<(String, ItemActionCapabilities, u64)> {
        self.retire_expired_human_item_grants()?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        retire_expired_grants_in_tx(&tx)?;
        authorization::ensure_source_credential_active(&tx, actor, credential)?;
        resolve_item_response_access_in_tx(&tx, file_id, actor, permission)?;
        let (workspace_id, capabilities) = item_action_capabilities_in_tx(&tx, file_id, actor)?;
        let access_generation = access_generation_in_tx(&tx)?;
        tx.commit()?;
        Ok((workspace_id, capabilities, access_generation))
    }
}

pub(super) fn item_action_capabilities_in_tx(
    tx: &Transaction<'_>,
    file_id: &str,
    actor: &Actor,
) -> ApiResult<(String, ItemActionCapabilities)> {
    let access = resolve_item_access_in_tx(tx, file_id, actor, WorkspacePermission::Read)?;
    let capabilities = if actor.is_admin
        || whole_workspace_role_in_tx(tx, &access.workspace_id, &actor.email)?.is_some()
    {
        workspace_action_capabilities_in_tx(tx, &access.workspace_id, actor)?
    } else {
        // A scoped viewer/editor may read the item, but must never gain a
        // workspace capability merely because the UI asked which controls to
        // render.
        ItemActionCapabilities::default()
    };
    Ok((access.workspace_id, capabilities))
}

pub(super) fn workspace_action_capabilities_in_tx(
    tx: &Transaction<'_>,
    workspace_id: &str,
    actor: &Actor,
) -> ApiResult<ItemActionCapabilities> {
    if actor.is_admin {
        return Ok(ItemActionCapabilities {
            manage_human_sharing: true,
            manage_guest_links: true,
            manage_ai_access: true,
        });
    }
    let role =
        whole_workspace_role_in_tx(tx, workspace_id, &actor.email)?.ok_or(ApiError::Forbidden)?;
    Ok(ItemActionCapabilities {
        // Human grants broaden a recipient's authority, so only a
        // whole-workspace owner can delegate them.
        manage_human_sharing: role == WorkspaceRole::Owner,
        // Guest-link and AI management retain their existing whole-workspace
        // Editor policy.  Item-only Editors never qualify because they do not
        // have a workspace role.
        manage_guest_links: role.allows(WorkspacePermission::Write),
        manage_ai_access: role.allows(WorkspacePermission::Write),
    })
}
