use chrono::Utc;
use rusqlite::{params, params_from_iter, OptionalExtension, Transaction};
use serde::Serialize;

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::Receipt,
    workspace_policy::checked_retention_cutoff,
};

use super::{
    authorization, default_workspace_policy, delete_file_roots_in_tx, insert_receipt_rows,
    new_receipt, recursive_file_ids_in_tx, retention_timestamp_due,
    sync::insert_workspace_rescan_sync_changes, workspace_exists, Storage,
};

#[derive(Debug, Serialize)]
pub struct RetainedTrashItem {
    pub file_id: String,
    pub name: String,
}

#[derive(Debug)]
pub struct EmptyTrashResult {
    pub deleted: usize,
    pub retained: Vec<RetainedTrashItem>,
    pub candidate_hashes: Vec<String>,
}

impl Storage {
    /// Delete only top-level trashed subtrees whose complete contents have
    /// reached the workspace retention cutoff. A recent or malformed child
    /// keeps the entire subtree, so a parent can never bypass retention.
    pub fn empty_workspace_trash(
        &self,
        workspace_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(EmptyTrashResult, Receipt)> {
        let receipt = new_receipt("file.trash.empty", &actor.email, Some(workspace_id));
        let result = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if !workspace_exists(&tx, workspace_id)? {
                return Err(ApiError::NotFound);
            }
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
            let retention_days: i64 = tx
                .query_row(
                    "SELECT trash_retention_days FROM workspace_policies WHERE workspace_id = ?1",
                    params![workspace_id],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or_else(|| default_workspace_policy(workspace_id).trash_retention_days);
            let cutoff = checked_retention_cutoff(Utc::now(), retention_days)?;
            let candidates = trash_roots(&tx, workspace_id)?;
            let mut eligible = Vec::new();
            let mut retained = Vec::new();
            for (file_id, name) in candidates {
                if subtree_reached_cutoff(&tx, &file_id, &cutoff, retention_days)? {
                    eligible.push(file_id);
                } else {
                    retained.push(RetainedTrashItem { file_id, name });
                }
            }
            // The receipt mapper cannot resolve roots after their deletion.
            // Capture the workspace and roots while the tree is still live,
            // then create one bounded manifest-rescan marker in this exact
            // transaction rather than attempting to infer it afterward.
            let affected_workspace_ids = if eligible.is_empty() {
                Vec::new()
            } else {
                vec![workspace_id.to_string()]
            };
            insert_receipt_rows(&tx, &receipt)?;
            insert_workspace_rescan_sync_changes(&tx, &affected_workspace_ids, &receipt)?;
            let (deleted, candidate_hashes) = delete_file_roots_in_tx(&tx, &eligible)?;
            tx.commit()?;
            EmptyTrashResult {
                deleted,
                retained,
                candidate_hashes,
            }
        };
        Ok((result, receipt))
    }
}

fn trash_roots(tx: &Transaction<'_>, workspace_id: &str) -> ApiResult<Vec<(String, String)>> {
    let mut statement = tx.prepare(
        "SELECT child.id, child.name
         FROM files child
         LEFT JOIN files parent ON parent.id = child.parent_id
         WHERE child.workspace_id = ?1
           AND child.trashed != 0
           AND (parent.id IS NULL OR parent.trashed = 0)
         ORDER BY child.name, child.id",
    )?;
    let rows = statement.query_map(params![workspace_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn subtree_reached_cutoff(
    tx: &Transaction<'_>,
    root_id: &str,
    cutoff: &chrono::DateTime<Utc>,
    retention_days: i64,
) -> ApiResult<bool> {
    let ids = recursive_file_ids_in_tx(tx, &[root_id.to_string()])?;
    if ids.is_empty() {
        return Ok(false);
    }
    let placeholders = std::iter::repeat_n("?", ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let mut statement = tx.prepare(&format!(
        "SELECT trashed, trashed_at FROM files WHERE id IN ({placeholders})"
    ))?;
    let rows = statement.query_map(params_from_iter(ids.iter()), |row| {
        Ok((row.get::<_, bool>(0)?, row.get::<_, Option<String>>(1)?))
    })?;
    for row in rows {
        let (trashed, trashed_at) = row?;
        let due = trashed_at
            .as_deref()
            .map(|value| retention_timestamp_due(value, cutoff, retention_days))
            .transpose()?
            .unwrap_or(false);
        if !trashed || !due {
            return Ok(false);
        }
    }
    Ok(true)
}
