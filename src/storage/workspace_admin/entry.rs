use crate::{
    auth::{Actor, DriveCredential},
    error::ApiResult,
    model::Receipt,
};

use super::super::Storage;

impl Storage {
    pub fn delete_empty_archived_workspace(
        &self,
        workspace_id: &str,
        actor: &str,
    ) -> ApiResult<Receipt> {
        self.delete_empty_archived_workspace_inner(workspace_id, actor, None)
    }

    pub(crate) fn delete_empty_archived_workspace_authorized(
        &self,
        workspace_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        self.delete_empty_archived_workspace_inner(
            workspace_id,
            &actor.email,
            Some((actor, source_credential)),
        )
    }
}
