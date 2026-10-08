use std::collections::{BTreeSet, HashSet};

use chrono::Utc;
use rusqlite::{params, params_from_iter, OptionalExtension};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{
        Receipt, RetentionRevisionCandidate, RetentionTotals, RetentionTrashCandidate, Workspace,
    },
    workspace_policy::checked_retention_cutoff,
};

use super::{
    authorization, delete_file_roots_in_tx,
    human_item_grants::access::ensure_item_authorized_in_tx, insert_receipt_rows, new_receipt,
    recursive_file_ids_in_tx, retention_timestamp_due, retention_totals,
    subtree_contains_live_file_in_tx, sync::insert_workspace_rescan_sync_changes,
    RetentionApplyOutput, Storage,
};

/// One retention request processes a visible, repeatable batch. Large stores
/// are pruned by invoking apply again, keeping both preview and apply memory
/// bounded while preserving the existing dry-run contract.
pub const MAX_RETENTION_CANDIDATES: usize = 10_000;
const MAX_RETENTION_WORKSPACES: i64 = 1_000;

impl Storage {
    pub fn preview_retention(
        &self,
        workspace_id: Option<&str>,
    ) -> ApiResult<(
        Vec<RetentionTrashCandidate>,
        Vec<RetentionRevisionCandidate>,
        RetentionTotals,
        bool,
    )> {
        self.preview_retention_inner(workspace_id, None)
    }

    pub(crate) fn preview_retention_authorized(
        &self,
        workspace_id: Option<&str>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(
        Vec<RetentionTrashCandidate>,
        Vec<RetentionRevisionCandidate>,
        RetentionTotals,
        bool,
    )> {
        self.preview_retention_inner(workspace_id, Some((actor, source_credential)))
    }

    fn preview_retention_inner(
        &self,
        workspace_id: Option<&str>,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(
        Vec<RetentionTrashCandidate>,
        Vec<RetentionRevisionCandidate>,
        RetentionTotals,
        bool,
    )> {
        let workspaces = self
            .retention_workspaces(workspace_id)?
            .into_iter()
            .map(|workspace| {
                let policy = self.get_workspace_policy(&workspace.id)?;
                Ok((workspace, policy))
            })
            .collect::<ApiResult<Vec<_>>>()?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        if let Some((actor, source_credential)) = authorization_context {
            if let Some(workspace_id) = workspace_id {
                authorization::ensure_workspace_authorized(
                    &tx,
                    workspace_id,
                    actor,
                    source_credential,
                    WorkspacePermission::Manage,
                )?;
            } else {
                authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
            }
        }
        let mut trash = Vec::new();
        let mut revisions = Vec::new();
        let mut more_available = false;
        'workspaces: for (workspace, policy) in workspaces {
            let trash_cutoff = checked_retention_cutoff(Utc::now(), policy.trash_retention_days)?;
            let query_limit = MAX_RETENTION_CANDIDATES
                .saturating_sub(trash.len() + revisions.len())
                .saturating_add(1) as i64;
            let mut trash_stmt = tx.prepare(
                "SELECT id, workspace_id, name, trashed_at, content_bytes, content_hash
                 FROM files
                 WHERE workspace_id = ?1
                   AND trashed != 0
                   AND trashed_at IS NOT NULL
                 ORDER BY trashed_at ASC
                 LIMIT ?2",
            )?;
            let trash_rows = trash_stmt.query_map(
                params![&workspace.id, query_limit],
                |row| -> rusqlite::Result<RetentionTrashCandidate> {
                    Ok(RetentionTrashCandidate {
                        file_id: row.get(0)?,
                        workspace_id: row.get(1)?,
                        name: row.get(2)?,
                        trashed_at: row.get(3)?,
                        retention_days: policy.trash_retention_days,
                        content_bytes: row.get(4)?,
                        content_hash: row.get(5)?,
                    })
                },
            )?;
            for candidate in trash_rows {
                let candidate = candidate?;
                if retention_timestamp_due(
                    &candidate.trashed_at,
                    &trash_cutoff,
                    policy.trash_retention_days,
                )? {
                    trash.push(candidate);
                    if trash.len() + revisions.len() > MAX_RETENTION_CANDIDATES {
                        trash.pop();
                        more_available = true;
                        break 'workspaces;
                    }
                }
            }

            let revision_cutoff =
                checked_retention_cutoff(Utc::now(), policy.revision_retention_days)?;
            let query_limit = MAX_RETENTION_CANDIDATES
                .saturating_sub(trash.len() + revisions.len())
                .saturating_add(1) as i64;
            let mut revision_stmt = tx.prepare(
                "SELECT fr.file_id, f.workspace_id, f.name, fr.revision, fr.created_at, fr.content_bytes, fr.content_hash
                 FROM file_revisions fr
                 JOIN files f ON f.id = fr.file_id
                 WHERE f.workspace_id = ?1
                   AND fr.pinned = 0
                   AND fr.revision < f.revision
                 ORDER BY fr.created_at ASC
                 LIMIT ?2",
            )?;
            let revision_rows = revision_stmt.query_map(
                params![&workspace.id, query_limit],
                |row| -> rusqlite::Result<RetentionRevisionCandidate> {
                    Ok(RetentionRevisionCandidate {
                        file_id: row.get(0)?,
                        workspace_id: row.get(1)?,
                        name: row.get(2)?,
                        revision: row.get(3)?,
                        created_at: row.get(4)?,
                        retention_days: policy.revision_retention_days,
                        content_bytes: row.get(5)?,
                        content_hash: row.get(6)?,
                    })
                },
            )?;
            for candidate in revision_rows {
                let candidate = candidate?;
                if retention_timestamp_due(
                    &candidate.created_at,
                    &revision_cutoff,
                    policy.revision_retention_days,
                )? {
                    revisions.push(candidate);
                    if trash.len() + revisions.len() > MAX_RETENTION_CANDIDATES {
                        revisions.pop();
                        more_available = true;
                        break 'workspaces;
                    }
                }
            }
        }
        let totals = retention_totals(&trash, &revisions);
        tx.commit()?;
        Ok((trash, revisions, totals, more_available))
    }

    pub fn apply_retention(
        &self,
        trash: &[RetentionTrashCandidate],
        revisions: &[RetentionRevisionCandidate],
        actor: &str,
        workspace_id: Option<&str>,
    ) -> ApiResult<RetentionApplyOutput> {
        self.apply_retention_inner(trash, revisions, actor, workspace_id, None)
    }

    pub(crate) fn apply_retention_authorized(
        &self,
        trash: &[RetentionTrashCandidate],
        revisions: &[RetentionRevisionCandidate],
        actor: &Actor,
        source_credential: &DriveCredential,
        workspace_id: Option<&str>,
    ) -> ApiResult<RetentionApplyOutput> {
        self.apply_retention_inner(
            trash,
            revisions,
            &actor.email,
            workspace_id,
            Some((actor, source_credential)),
        )
    }

    fn apply_retention_inner(
        &self,
        trash: &[RetentionTrashCandidate],
        revisions: &[RetentionRevisionCandidate],
        actor: &str,
        workspace_id: Option<&str>,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<RetentionApplyOutput> {
        let receipt = new_receipt("retention.prune", actor, workspace_id);
        let (hashes, applied_trash, applied_revisions) = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if let Some((actor, source_credential)) = authorization_context {
                if let Some(workspace_id) = workspace_id {
                    authorization::ensure_workspace_authorized(
                        &tx,
                        workspace_id,
                        actor,
                        source_credential,
                        WorkspacePermission::Manage,
                    )?;
                } else {
                    authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
                }
            }
            let now = Utc::now();
            let mut file_ids = Vec::new();
            let mut applied_trash = Vec::new();
            let mut affected_workspace_ids = BTreeSet::new();
            for candidate in trash {
                let current = tx
                    .query_row(
                        "SELECT f.trashed_at, COALESCE(p.trash_retention_days, 30)
                         FROM files f
                         LEFT JOIN workspace_policies p ON p.workspace_id = f.workspace_id
                         WHERE f.id = ?1 AND f.workspace_id = ?2 AND f.trashed != 0",
                        params![&candidate.file_id, &candidate.workspace_id],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .optional()?;
                let Some((trashed_at, retention_days)) = current else {
                    continue;
                };
                let cutoff = checked_retention_cutoff(now, retention_days)?;
                if !retention_timestamp_due(&trashed_at, &cutoff, retention_days)?
                    || subtree_contains_live_file_in_tx(&tx, &candidate.file_id)?
                {
                    continue;
                }
                file_ids.push(candidate.file_id.clone());
                applied_trash.push(candidate.clone());
                affected_workspace_ids.insert(candidate.workspace_id.clone());
            }
            let deleted_file_ids = recursive_file_ids_in_tx(&tx, &file_ids)?
                .into_iter()
                .collect::<HashSet<_>>();

            let mut applied_revisions = Vec::new();
            let mut hashes = Vec::new();
            for revision in revisions {
                // A trash-root deletion cascades its revisions. Preserve the
                // previous apply semantics by not also reporting those
                // revisions as independently pruned retention candidates.
                if deleted_file_ids.contains(&revision.file_id) {
                    continue;
                }
                let current = tx
                    .query_row(
                        "SELECT fr.content_hash, fr.created_at, f.revision,
                                COALESCE(p.revision_retention_days, 90)
                         FROM file_revisions fr
                         JOIN files f ON f.id = fr.file_id
                         LEFT JOIN workspace_policies p ON p.workspace_id = f.workspace_id
                         WHERE fr.file_id = ?1 AND fr.revision = ?2
                           AND f.workspace_id = ?3 AND fr.pinned = 0
                           AND fr.revision < f.revision",
                        params![&revision.file_id, revision.revision, &revision.workspace_id],
                        |row| {
                            Ok((
                                row.get::<_, Option<String>>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, i64>(3)?,
                            ))
                        },
                    )
                    .optional()?;
                let Some((hash, created_at, _current_revision, retention_days)) = current else {
                    continue;
                };
                let cutoff = checked_retention_cutoff(now, retention_days)?;
                if !retention_timestamp_due(&created_at, &cutoff, retention_days)? {
                    continue;
                }
                if let Some(hash) = hash {
                    hashes.push(hash);
                }
                applied_revisions.push(revision.clone());
                affected_workspace_ids.insert(revision.workspace_id.clone());
            }

            // Resolve every affected workspace and root before removing any
            // row.  A single, explicit rescan event per workspace is bounded
            // and remains meaningful after its files/revisions disappear.
            let affected_workspace_ids = affected_workspace_ids.into_iter().collect::<Vec<_>>();
            insert_receipt_rows(&tx, &receipt)?;
            insert_workspace_rescan_sync_changes(&tx, &affected_workspace_ids, &receipt)?;

            let (_, deleted_hashes) = delete_file_roots_in_tx(&tx, &file_ids)?;
            hashes.extend(deleted_hashes);
            for revision in &applied_revisions {
                tx.execute(
                    "DELETE FROM file_revisions WHERE file_id = ?1 AND revision = ?2 AND pinned = 0",
                    params![&revision.file_id, revision.revision],
                )?;
            }
            tx.commit()?;
            (hashes, applied_trash, applied_revisions)
        };
        Ok((receipt, hashes, applied_trash, applied_revisions))
    }

    /// Whether the given blob hash is still referenced by any live row.
    ///
    /// Counts file content, historical revisions, preview thumbnails, and
    /// folder cover images: all four share the single content-addressed blob
    /// store, so an identical image stored as a file and reused as another
    /// file's thumbnail or a folder's cover must keep its blob until every
    /// reference is gone.
    pub fn content_hash_is_referenced(&self, hash: &str) -> ApiResult<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT
                (SELECT COUNT(*) FROM files WHERE content_hash = ?1) +
                (SELECT COUNT(*) FROM files WHERE cover_hash = ?1) +
                (SELECT COUNT(*) FROM file_revisions WHERE content_hash = ?1) +
                (SELECT COUNT(*) FROM file_previews WHERE thumbnail_hash = ?1)",
            params![hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Resolve a bounded GC candidate set in one indexed statement. Returning
    /// the referenced subset avoids one database round-trip per on-disk blob.
    pub(crate) fn referenced_content_hashes(
        &self,
        hashes: &[String],
    ) -> ApiResult<HashSet<String>> {
        if hashes.is_empty() {
            return Ok(HashSet::new());
        }
        if hashes.len() > crate::blob::MAX_GC_BATCH_SIZE {
            return Err(ApiError::PayloadTooLarge(format!(
                "blob GC reference batch exceeds {} hashes",
                crate::blob::MAX_GC_BATCH_SIZE
            )));
        }
        let values = std::iter::repeat_n("(?)", hashes.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "WITH candidates(hash) AS (VALUES {values})
             SELECT files.content_hash
             FROM candidates
             JOIN files INDEXED BY idx_files_content_hash_referenced
               ON candidates.hash = files.content_hash
             WHERE files.content_hash IS NOT NULL
             UNION
             SELECT files.cover_hash
             FROM candidates
             JOIN files INDEXED BY idx_files_cover_hash_referenced
               ON candidates.hash = files.cover_hash
             WHERE files.cover_hash IS NOT NULL
             UNION
             SELECT file_revisions.content_hash
             FROM candidates
             JOIN file_revisions INDEXED BY idx_file_revisions_content_hash_referenced
               ON candidates.hash = file_revisions.content_hash
             WHERE file_revisions.content_hash IS NOT NULL
             UNION
             SELECT file_previews.thumbnail_hash
             FROM candidates
             JOIN file_previews INDEXED BY idx_file_previews_thumbnail_hash_referenced
               ON candidates.hash = file_previews.thumbnail_hash
             WHERE file_previews.thumbnail_hash IS NOT NULL"
        );
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(hashes.iter()), |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<HashSet<_>>>()?)
    }

    /// Permanently delete a file (or folder, recursively) and every one of its
    /// revisions and preview rows. Returns the set of blob hashes that *were*
    /// referenced by the removed rows so the caller can reference-count them
    /// against remaining rows and reclaim any now-orphaned blobs.
    pub fn permanently_delete_file(
        &self,
        file_id: &str,
        actor: &str,
    ) -> ApiResult<(Vec<String>, Receipt)> {
        self.permanently_delete_file_inner(file_id, actor, None)
    }

    pub(crate) fn permanently_delete_file_authorized(
        &self,
        file_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(Vec<String>, Receipt)> {
        self.permanently_delete_file_inner(file_id, &actor.email, Some((actor, source_credential)))
    }

    fn permanently_delete_file_inner(
        &self,
        file_id: &str,
        receipt_actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(Vec<String>, Receipt)> {
        let receipt = new_receipt("file.delete", receipt_actor, Some(file_id));
        let hashes = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let (workspace_id, trashed) = tx
                .query_row(
                    "SELECT workspace_id, trashed FROM files WHERE id = ?1",
                    params![file_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0)),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if let Some((actor, source_credential)) = authorization_context {
                if trashed {
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
                        file_id,
                        actor,
                        source_credential,
                        WorkspacePermission::Write,
                    )?;
                    // Live item grants exclude retained descendants. Check
                    // the exact destructive set before publishing a receipt
                    // or deleting any row, while this transaction holds it
                    // stable for the recursive deletion below.
                    let ids = recursive_file_ids_in_tx(&tx, &[file_id.to_string()])?;
                    let placeholders = std::iter::repeat_n("?", ids.len())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let contains_retained: bool = tx.query_row(
                        &format!(
                            "SELECT EXISTS(SELECT 1 FROM files
                             WHERE id IN ({placeholders}) AND trashed != 0)"
                        ),
                        params_from_iter(ids.iter()),
                        |row| row.get(0),
                    )?;
                    if contains_retained {
                        authorization::ensure_workspace_authorized(
                            &tx,
                            &workspace_id,
                            actor,
                            source_credential,
                            WorkspacePermission::Write,
                        )?;
                    }
                }
            }
            // Infer and persist the deletion tombstone while the file still
            // identifies its workspace, then remove the tree in the same
            // transaction. A crash can expose neither half on its own.
            insert_receipt_rows(&tx, &receipt)?;
            let (_, hashes) = delete_file_roots_in_tx(&tx, &[file_id.to_string()])?;
            tx.commit()?;
            hashes
        };
        Ok((hashes, receipt))
    }

    /// Collect every blob hash referenced by the already-resolved destructive
    /// set. The caller computes that set with the workspace-bound recursive
    /// helper in the same transaction, so this query must not independently
    /// follow untrusted parent links again.
    pub(super) fn collect_blob_hashes_for_file_ids(
        tx: &rusqlite::Transaction<'_>,
        ids: &[String],
    ) -> ApiResult<Vec<String>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = std::iter::repeat_n("(?)", ids.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "WITH doomed(id) AS (VALUES {placeholders})
             SELECT files.content_hash AS hash
             FROM files JOIN doomed ON doomed.id = files.id
              WHERE files.content_hash IS NOT NULL
             UNION ALL
             SELECT files.cover_hash AS hash
             FROM files JOIN doomed ON doomed.id = files.id
              WHERE files.cover_hash IS NOT NULL
             UNION ALL
             SELECT file_revisions.content_hash AS hash
             FROM file_revisions JOIN doomed ON doomed.id = file_revisions.file_id
              WHERE file_revisions.content_hash IS NOT NULL
             UNION ALL
             SELECT file_previews.thumbnail_hash AS hash
             FROM file_previews JOIN doomed ON doomed.id = file_previews.file_id
              WHERE file_previews.thumbnail_hash IS NOT NULL"
        );
        let mut statement = tx.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(ids.iter()), |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn retention_workspaces(&self, workspace_id: Option<&str>) -> ApiResult<Vec<Workspace>> {
        if let Some(workspace_id) = workspace_id {
            let workspace = self
                .get_workspace(workspace_id)?
                .ok_or(ApiError::NotFound)?;
            return Ok(vec![workspace]);
        }
        let workspaces = self.list_workspaces_bounded(MAX_RETENTION_WORKSPACES + 1)?;
        if workspaces.len() > MAX_RETENTION_WORKSPACES as usize {
            return Err(ApiError::PayloadTooLarge(format!(
                "global retention supports at most {MAX_RETENTION_WORKSPACES} workspaces per request; select one workspace"
            )));
        }
        Ok(workspaces)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CreateFileRequest, FileKind};

    #[test]
    fn gc_reference_lookup_resolves_a_candidate_set_in_one_query() {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::open(root.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let (workspace, _, _) = storage
            .create_workspace("GC", "owner@example.test")
            .unwrap();
        let referenced = "1".repeat(64);
        let orphan = "2".repeat(64);
        storage
            .create_file_with_content_bytes(
                CreateFileRequest {
                    workspace_id: workspace.id,
                    parent_id: None,
                    name: "referenced.bin".to_string(),
                    kind: FileKind::File,
                    content: None,
                    path: None,
                },
                Some(referenced.clone()),
                1,
            )
            .unwrap();

        let resolved = storage
            .referenced_content_hashes(&[orphan.clone(), referenced.clone()])
            .unwrap();
        assert_eq!(resolved, HashSet::from([referenced]));
        assert!(!resolved.contains(&orphan));
    }
}
