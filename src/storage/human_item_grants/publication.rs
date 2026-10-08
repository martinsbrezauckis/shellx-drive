use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{SharedByMeRoot, SharedItemRoot},
};

use super::{
    super::{authorization, Storage},
    access::{resolve_item_access_in_tx, retire_expired_grants_in_tx},
    capabilities::item_action_capabilities_in_tx,
    shared_by_me::shared_by_me_root_in_tx,
    sync_roots::resolve_sync_root_in_tx,
};

impl Storage {
    /// Publish a complete shared-with-me page only after all its roots have
    /// been rechecked within one snapshot; stale pages fail as a unit.
    pub fn revalidate_shared_item_roots_publication_authorized(
        &self,
        roots: &[SharedItemRoot],
        actor: &Actor,
        credential: &DriveCredential,
    ) -> ApiResult<Vec<SharedItemRoot>> {
        self.retire_expired_human_item_grants()?;
        if roots.len() > 100 {
            return Err(ApiError::PayloadTooLarge(
                "shared root page exceeds limit".to_string(),
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        retire_expired_grants_in_tx(&tx)?;
        authorization::ensure_source_credential_active(&tx, actor, credential)?;
        let actor = Actor {
            is_admin: false,
            ..actor.clone()
        };
        let mut revalidated = Vec::with_capacity(roots.len());
        for root in roots {
            let current = resolve_sync_root_in_tx(&tx, &root.sync_root_id, &actor)?;
            match root.grant_id.as_deref() {
                Some(_) if current.root_file_id.as_deref() != Some(root.file.id.as_str()) => {
                    return Err(ApiError::NotFound);
                }
                None if current.root_file_id.is_some()
                    || current.workspace_id != root.workspace_id =>
                {
                    return Err(ApiError::NotFound);
                }
                _ => {}
            }
            resolve_item_access_in_tx(&tx, &root.file.id, &actor, WorkspacePermission::Read)?;
            let (_, action_capabilities) =
                item_action_capabilities_in_tx(&tx, &root.file.id, &actor)?;
            let mut root = root.clone();
            root.access_generation = current.access_generation;
            root.action_capabilities = action_capabilities;
            revalidated.push(root);
        }
        tx.commit()?;
        Ok(revalidated)
    }

    pub fn revalidate_shared_by_me_publication_authorized(
        &self,
        roots: &[SharedByMeRoot],
        actor: &Actor,
        credential: &DriveCredential,
    ) -> ApiResult<Vec<SharedByMeRoot>> {
        self.retire_expired_human_item_grants()?;
        if roots.len() > 100 {
            return Err(ApiError::PayloadTooLarge(
                "shared-by-me page exceeds limit".to_string(),
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        retire_expired_grants_in_tx(&tx)?;
        authorization::ensure_source_credential_active(&tx, actor, credential)?;
        let mut revalidated = Vec::with_capacity(roots.len());
        for root in roots {
            if let Some(root) = shared_by_me_root_in_tx(&tx, &root.file.id, actor)? {
                revalidated.push(root);
            }
        }
        tx.commit()?;
        Ok(revalidated)
    }
}
