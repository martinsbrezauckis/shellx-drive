use chrono::Utc;
use rusqlite::{params, TransactionBehavior};
use uuid::Uuid;

use crate::{
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind, Receipt},
    storage::{
        insert_receipt_rows, new_receipt, refresh_file_search_index_locked, validate_file_name,
        Storage,
    },
};

use super::{
    active_grant_locked, agent_receipt_actor, ensure_file_in_scope_locked, query_file_locked,
    AgentFileUpdate,
};

impl Storage {
    pub fn update_agent_file(
        &self,
        principal_id: &str,
        token_id: &str,
        grant_id: &str,
        file_id: &str,
        update: AgentFileUpdate,
    ) -> ApiResult<(DriveFile, Receipt)> {
        let validated_name = update.name.as_deref().map(validate_file_name).transpose()?;
        let collision_policy =
            crate::storage::file_destination::parse_destination_collision_policy(
                update.collision_policy.as_deref(),
            )?;
        let updated_at = Utc::now().to_rfc3339();
        let receipt_actor = agent_receipt_actor(principal_id, token_id);
        let file = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let access = active_grant_locked(&tx, principal_id, token_id, grant_id, true)?;
            let current = ensure_file_in_scope_locked(&tx, &access, file_id, None)?;
            if current.id == access.root_file_id {
                return Err(ApiError::Forbidden);
            }
            if update
                .base_revision
                .is_some_and(|revision| revision != current.revision)
            {
                return Err(ApiError::PreconditionFailed);
            }
            let next_parent = match update.parent_id.as_deref() {
                Some(destination_id) => {
                    let destination =
                        ensure_file_in_scope_locked(&tx, &access, destination_id, Some(file_id))?;
                    if !matches!(destination.kind, FileKind::Folder) {
                        return Err(ApiError::Validation("parent must be a folder".to_string()));
                    }
                    Some(destination.id)
                }
                None => current.parent_id.clone(),
            };
            let next_name = validated_name
                .clone()
                .unwrap_or_else(|| current.name.clone());
            let destination = if next_parent != current.parent_id || next_name != current.name {
                crate::storage::file_destination::resolve_move_destination_in_tx(
                    &tx,
                    &current,
                    next_parent.as_deref(),
                    &next_name,
                    collision_policy,
                    &updated_at,
                )?
            } else {
                crate::storage::file_destination::ResolvedMoveDestination::Move(next_name)
            };
            let (file, receipt) = match destination {
                crate::storage::file_destination::ResolvedMoveDestination::Move(next_name) => {
                    let next_revision = current.revision + 1;
                    if tx.execute(
                        "UPDATE files SET name = ?1, parent_id = ?2, revision = ?3,
                                          updated_at = ?4
                         WHERE id = ?5 AND revision = ?6",
                        params![
                            next_name,
                            next_parent,
                            next_revision,
                            updated_at,
                            file_id,
                            current.revision,
                        ],
                    )? != 1
                    {
                        return Err(ApiError::Conflict);
                    }
                    tx.execute(
                        "INSERT INTO file_revisions (
                            id, file_id, revision, content_hash, content_bytes,
                            created_at, conflict_of_revision
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                        params![
                            Uuid::now_v7().to_string(),
                            file_id,
                            next_revision,
                            current.content_hash,
                            current.size_bytes.unwrap_or(0),
                            updated_at,
                        ],
                    )?;
                    refresh_file_search_index_locked(&tx, file_id)?;
                    let file = query_file_locked(&tx, file_id)?.ok_or(ApiError::NotFound)?;
                    let receipt = new_receipt("agent.file.update", &receipt_actor, Some(file_id));
                    insert_receipt_rows(&tx, &receipt)?;
                    (file, receipt)
                }
                crate::storage::file_destination::ResolvedMoveDestination::Replace(target) => {
                    if update.base_revision.is_none()
                        || update.replace_target_id.is_none()
                        || update.replace_target_revision.is_none()
                    {
                        return Err(ApiError::Validation(
                            "replace requires base_revision, replace_target_id, and replace_target_revision"
                                .to_string(),
                        ));
                    }
                    if update.replace_target_id.as_deref() != Some(target.id.as_str())
                        || update.replace_target_revision != Some(target.revision)
                    {
                        return Err(ApiError::PreconditionFailed);
                    }
                    let target = ensure_file_in_scope_locked(&tx, &access, &target.id, None)?;
                    let file =
                        crate::storage::file_destination::replace_source_at_destination_in_tx(
                            &tx,
                            &current,
                            &target,
                            None,
                            None,
                            &updated_at,
                        )?;
                    refresh_file_search_index_locked(&tx, &current.id)?;
                    refresh_file_search_index_locked(&tx, &file.id)?;
                    let source_receipt =
                        new_receipt("agent.file.trash", &receipt_actor, Some(file_id));
                    let receipt = new_receipt("agent.file.replace", &receipt_actor, Some(&file.id));
                    insert_receipt_rows(&tx, &source_receipt)?;
                    insert_receipt_rows(&tx, &receipt)?;
                    (file, receipt)
                }
            };
            tx.commit()?;
            (file, receipt)
        };
        Ok(file)
    }
}
