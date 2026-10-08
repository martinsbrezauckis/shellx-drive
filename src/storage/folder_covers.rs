use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{DriveFile, Receipt},
};

use super::{
    authorization, enforce_cover_quota_in_txn,
    human_item_grants::access::ensure_item_authorized_in_tx, insert_receipt_rows, new_receipt,
    validate_non_negative_i64, Storage,
};

impl Storage {
    /// Return the raw cover-image blob hash for a folder, or `None` when the
    /// folder has no cover set. Used by the cover-serve route; the hash is never
    /// surfaced to clients (only the `has_cover` boolean is).
    pub fn folder_cover_hash(&self, folder_id: &str) -> ApiResult<Option<String>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT cover_hash FROM files WHERE id = ?1",
            params![folder_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .ok_or(ApiError::NotFound)
    }

    /// Point a folder's cover image at `cover_hash` (the SHA-256 of an
    /// already-stored image blob). Returns the updated folder, the *previous*
    /// cover hash (so the caller can reference-count and reclaim a replaced
    /// blob), and a receipt. Caller must have validated `folder_id` is a folder.
    pub fn set_folder_cover(
        &self,
        folder_id: &str,
        cover_hash: &str,
        cover_bytes: i64,
    ) -> ApiResult<(DriveFile, Option<String>, Receipt)> {
        self.set_folder_cover_as(folder_id, cover_hash, cover_bytes, "system")
    }

    pub fn set_folder_cover_as(
        &self,
        folder_id: &str,
        cover_hash: &str,
        cover_bytes: i64,
        actor: &str,
    ) -> ApiResult<(DriveFile, Option<String>, Receipt)> {
        self.set_folder_cover_inner(folder_id, cover_hash, cover_bytes, actor, None)
    }

    pub(crate) fn set_folder_cover_authorized(
        &self,
        folder_id: &str,
        cover_hash: &str,
        cover_bytes: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DriveFile, Option<String>, Receipt)> {
        self.set_folder_cover_inner(
            folder_id,
            cover_hash,
            cover_bytes,
            &actor.email,
            Some((actor, source_credential)),
        )
    }

    fn set_folder_cover_inner(
        &self,
        folder_id: &str,
        cover_hash: &str,
        cover_bytes: i64,
        receipt_actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(DriveFile, Option<String>, Receipt)> {
        let cover_bytes = validate_non_negative_i64(cover_bytes, "cover_bytes")?;
        if cover_bytes == 0 {
            return Err(ApiError::Validation(
                "cover bytes must be positive".to_string(),
            ));
        }
        let updated_at = Utc::now().to_rfc3339();
        let receipt = new_receipt("folder.cover.set", receipt_actor, Some(folder_id));
        let previous = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let (workspace_id, previous, trashed): (String, Option<String>, i64) = tx
                .query_row(
                    "SELECT workspace_id, cover_hash, trashed FROM files WHERE id = ?1",
                    params![folder_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if let Some((actor, source_credential)) = authorization_context {
                if trashed != 0 {
                    // A trashed folder is outside every live item grant. Like
                    // restore, mutating its retained cover therefore requires
                    // a workspace-wide writer, never a stale item grant.
                    authorization::ensure_workspace_authorized(
                        &tx,
                        &workspace_id,
                        actor,
                        source_credential,
                        WorkspacePermission::Write,
                    )?;
                } else {
                    ensure_item_authorized_in_tx(
                        &tx,
                        folder_id,
                        actor,
                        source_credential,
                        WorkspacePermission::Write,
                    )?;
                }
            }
            let quota_bytes = tx
                .query_row(
                    "SELECT quota_bytes FROM workspace_policies WHERE workspace_id = ?1",
                    params![&workspace_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten();
            if let Some(quota_bytes) = quota_bytes {
                enforce_cover_quota_in_txn(
                    &tx,
                    quota_bytes,
                    &workspace_id,
                    folder_id,
                    cover_bytes,
                )?;
            }
            tx.execute(
                "UPDATE files
                 SET cover_hash = ?1, cover_bytes = ?2, updated_at = ?3
                 WHERE id = ?4",
                params![cover_hash, cover_bytes, &updated_at, folder_id],
            )?;
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
            previous
        };
        let file = self.get_file(folder_id)?.ok_or(ApiError::NotFound)?;
        Ok((file, previous, receipt))
    }

    /// Clear a folder's cover image. Returns the updated folder, the *previous*
    /// cover hash (so the caller can reclaim the now-unreferenced blob), and a
    /// receipt.
    pub fn clear_folder_cover(
        &self,
        folder_id: &str,
    ) -> ApiResult<(DriveFile, Option<String>, Receipt)> {
        self.clear_folder_cover_as(folder_id, "system")
    }

    pub fn clear_folder_cover_as(
        &self,
        folder_id: &str,
        actor: &str,
    ) -> ApiResult<(DriveFile, Option<String>, Receipt)> {
        self.clear_folder_cover_inner(folder_id, actor, None)
    }

    pub(crate) fn clear_folder_cover_authorized(
        &self,
        folder_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DriveFile, Option<String>, Receipt)> {
        self.clear_folder_cover_inner(folder_id, &actor.email, Some((actor, source_credential)))
    }

    fn clear_folder_cover_inner(
        &self,
        folder_id: &str,
        receipt_actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(DriveFile, Option<String>, Receipt)> {
        let updated_at = Utc::now().to_rfc3339();
        let receipt = new_receipt("folder.cover.clear", receipt_actor, Some(folder_id));
        let previous = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let (workspace_id, previous, trashed): (String, Option<String>, i64) = tx
                .query_row(
                    "SELECT workspace_id, cover_hash, trashed FROM files WHERE id = ?1",
                    params![folder_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if let Some((actor, source_credential)) = authorization_context {
                if trashed != 0 {
                    authorization::ensure_workspace_authorized(
                        &tx,
                        &workspace_id,
                        actor,
                        source_credential,
                        WorkspacePermission::Write,
                    )?;
                } else {
                    ensure_item_authorized_in_tx(
                        &tx,
                        folder_id,
                        actor,
                        source_credential,
                        WorkspacePermission::Write,
                    )?;
                }
            }
            tx.execute(
                "UPDATE files
                 SET cover_hash = NULL, cover_bytes = 0, updated_at = ?1
                 WHERE id = ?2",
                params![&updated_at, folder_id],
            )?;
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
            previous
        };
        let file = self.get_file(folder_id)?.ok_or(ApiError::NotFound)?;
        Ok((file, previous, receipt))
    }
}
