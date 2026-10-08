use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::Receipt,
};

use super::{authorization, insert_receipt_rows, Storage};

impl Storage {
    fn delete_empty_archived_workspace_inner(
        &self,
        workspace_id: &str,
        receipt_actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<Receipt> {
        let receipt = Receipt {
            id: Uuid::now_v7().to_string(),
            kind: "workspace.delete.empty_archived".to_string(),
            actor: receipt_actor.to_string(),
            target_id: Some(workspace_id.to_string()),
            created_at: Utc::now().to_rfc3339(),
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((actor, source_credential)) = authorization_context {
            authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        }
        let archived_at = tx
            .query_row(
                "SELECT archived_at FROM workspaces WHERE id = ?1",
                [workspace_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        if archived_at.is_none() {
            return Err(ApiError::Validation(
                "workspace must be archived before permanent deletion".to_string(),
            ));
        }
        let file_count = tx.query_row(
            "SELECT COUNT(*) FROM files WHERE workspace_id = ?1",
            [workspace_id],
            |row| row.get::<_, i64>(0),
        )?;
        if file_count != 0 {
            return Err(ApiError::Validation(
                "only empty archived workspaces can be permanently deleted".to_string(),
            ));
        }
        tx.execute(
            "DELETE FROM sync_changes WHERE workspace_id = ?1",
            params![workspace_id],
        )?;
        tx.execute(
            "DELETE FROM sync_change_floors WHERE workspace_id = ?1",
            params![workspace_id],
        )?;
        tx.execute(
            "DELETE FROM sync_change_counts WHERE workspace_id = ?1",
            params![workspace_id],
        )?;
        cleanup::delete_workspace_attributed_delivery_rows(&tx, workspace_id)?;
        let deleted = tx.execute(
            "DELETE FROM workspaces WHERE id = ?1 AND archived_at IS NOT NULL",
            params![workspace_id],
        )?;
        if deleted != 1 {
            return Err(ApiError::NotFound);
        }
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }
}

mod cleanup;
mod entry;
