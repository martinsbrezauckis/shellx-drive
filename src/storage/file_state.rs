use std::collections::HashSet;

use chrono::Utc;
use rusqlite::{params, params_from_iter, types::ToSql, OptionalExtension};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{
        BulkFileActionRequest, BulkFileActionResponse, DriveFile, Receipt, MAX_BULK_FILE_ACTIONS,
    },
};

use super::{
    authorization, background_jobs, file_destination::ensure_restore_destinations_available_in_tx,
    human_item_grants::access::ensure_item_authorized_in_tx, insert_receipt_rows, new_receipt,
    recursive_file_ids_in_tx, row_to_file, validate_parent_chain_in_tx, Storage,
};

impl Storage {
    pub fn set_trashed(&self, file_id: &str, trashed: bool) -> ApiResult<(DriveFile, Receipt)> {
        self.set_trashed_as(file_id, trashed, "system")
    }

    pub fn set_trashed_as(
        &self,
        file_id: &str,
        trashed: bool,
        actor: &str,
    ) -> ApiResult<(DriveFile, Receipt)> {
        self.set_trashed_inner(file_id, trashed, actor, None)
    }

    pub(crate) fn set_trashed_authorized(
        &self,
        file_id: &str,
        trashed: bool,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DriveFile, Receipt)> {
        self.set_trashed_inner(
            file_id,
            trashed,
            &actor.email,
            Some((actor, source_credential)),
        )
    }

    fn set_trashed_inner(
        &self,
        file_id: &str,
        trashed: bool,
        receipt_actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(DriveFile, Receipt)> {
        let updated_at = Utc::now().to_rfc3339();
        let action = if trashed {
            FileStateAction::Trash
        } else {
            FileStateAction::Restore
        };
        let receipt_kind = if trashed {
            "file.trash"
        } else {
            "file.restore"
        };
        let receipt = new_receipt(receipt_kind, receipt_actor, Some(file_id));
        let file = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let root = tx
                .query_row(
                    "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                            content_hash, created_at, updated_at, content_bytes, cover_hash
                     FROM files WHERE id = ?1",
                    params![file_id],
                    row_to_file,
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if let Some((actor, source_credential)) = authorization_context {
                ensure_file_state_action_authorized_in_tx(
                    &tx,
                    &root,
                    action,
                    actor,
                    source_credential,
                )?;
            }
            let ids = recursive_file_ids_in_tx(&tx, std::slice::from_ref(&root.id))?;
            // A parent can be live while a retained descendant is already in
            // trash. Trashing that parent is still a valid transition: retain
            // the child's original trash metadata and transition only the live
            // members of the subtree. Restore remains an all-or-nothing
            // transition because reviving a mixed retained tree would change
            // its restoration intent.
            if trashed {
                validate_file_state_action_in_tx(&tx, std::slice::from_ref(&root.id), action)?;
            } else {
                validate_file_state_action_in_tx(&tx, &ids, action)?;
            }

            if !trashed {
                if let Some(parent_id) = root.parent_id.as_deref() {
                    validate_parent_chain_in_tx(
                        &tx,
                        &root.workspace_id,
                        parent_id,
                        Some(&root.id),
                    )?;
                }
                ensure_restore_destinations_available_in_tx(&tx, std::slice::from_ref(&root))?;
            }

            let placeholders = std::iter::repeat_n("?", ids.len())
                .collect::<Vec<_>>()
                .join(", ");
            let trashed_value = if trashed { 1_i64 } else { 0_i64 };
            let trashed_at = trashed.then_some(updated_at.as_str());
            let mut update_params: Vec<&dyn ToSql> = vec![&trashed_value, &trashed_at, &updated_at];
            update_params.extend(ids.iter().map(|id| id as &dyn ToSql));
            tx.execute(
                &format!(
                    "UPDATE files
                     SET revision = revision + 1,
                         trashed = ?1,
                         trashed_at = ?2,
                         updated_at = ?3
                     WHERE id IN ({placeholders}){}
                    ",
                    if trashed { " AND trashed = 0" } else { "" },
                ),
                params_from_iter(update_params),
            )?;
            if trashed {
                tx.execute(
                    &format!("DELETE FROM mobile_offline_files WHERE file_id IN ({placeholders})"),
                    params_from_iter(ids.iter()),
                )?;
            } else {
                let restored_files = {
                    let mut statement = tx.prepare(&format!(
                        "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                                content_hash, created_at, updated_at, content_bytes, cover_hash
                         FROM files
                         WHERE id IN ({placeholders}) AND kind = 'file' AND trashed = 0"
                    ))?;
                    let restored_files = statement
                        .query_map(params_from_iter(ids.iter()), row_to_file)?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    restored_files
                };
                for restored_file in restored_files {
                    let _ =
                        background_jobs::enqueue_file_background_jobs_in_tx(&tx, &restored_file)?;
                }
            }
            let file = tx.query_row(
                "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                        content_hash, created_at, updated_at, content_bytes, cover_hash
                 FROM files WHERE id = ?1",
                params![file_id],
                row_to_file,
            )?;
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
            file
        };
        Ok((file, receipt))
    }

    pub fn bulk_file_action(
        &self,
        request: BulkFileActionRequest,
        actor: &str,
    ) -> ApiResult<BulkFileActionResponse> {
        self.bulk_file_action_inner(request, actor, None)
    }

    pub(crate) fn bulk_file_action_authorized(
        &self,
        request: BulkFileActionRequest,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<BulkFileActionResponse> {
        self.bulk_file_action_inner(request, &actor.email, Some((actor, source_credential)))
    }

    fn bulk_file_action_inner(
        &self,
        request: BulkFileActionRequest,
        receipt_actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<BulkFileActionResponse> {
        let action = FileStateAction::parse(&request.action)?;
        if request.file_ids.is_empty() {
            return Err(ApiError::Validation("file_ids cannot be empty".to_string()));
        }
        if request.file_ids.len() > MAX_BULK_FILE_ACTIONS {
            return Err(ApiError::PayloadTooLarge(format!(
                "select no more than {MAX_BULK_FILE_ACTIONS} items at once"
            )));
        }
        let unique_ids = request.file_ids.iter().collect::<HashSet<_>>();
        if unique_ids.len() != request.file_ids.len() {
            return Err(ApiError::Validation(
                "file_ids must not contain duplicates".to_string(),
            ));
        }

        let kind = format!("file.bulk.{}", action.as_str());
        let receipt = new_receipt(&kind, receipt_actor, None);
        let files = if action.is_lifecycle() {
            self.bulk_set_trashed(&request.file_ids, action, &receipt, authorization_context)?
        } else {
            self.bulk_set_starred(&request.file_ids, action, &receipt, authorization_context)?
        };

        Ok(BulkFileActionResponse { files, receipt })
    }

    fn bulk_set_trashed(
        &self,
        file_ids: &[String],
        action: FileStateAction,
        receipt: &Receipt,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<Vec<DriveFile>> {
        debug_assert!(action.is_lifecycle());
        let updated_at = Utc::now().to_rfc3339();
        let root_ids = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let roots = bulk_lifecycle_roots_in_tx(&tx, file_ids)?;
            if let Some((actor, source_credential)) = authorization_context {
                for root in &roots {
                    ensure_file_state_action_authorized_in_tx(
                        &tx,
                        root,
                        action,
                        actor,
                        source_credential,
                    )?;
                }
            }
            let root_ids = roots.iter().map(|file| file.id.clone()).collect::<Vec<_>>();
            let ids = recursive_file_ids_in_tx(&tx, &root_ids)?;
            if action == FileStateAction::Trash {
                validate_file_state_action_in_tx(&tx, &root_ids, action)?;
            } else {
                validate_file_state_action_in_tx(&tx, &ids, action)?;
            }

            if action == FileStateAction::Restore {
                for root in &roots {
                    if let Some(parent_id) = root.parent_id.as_deref() {
                        validate_parent_chain_in_tx(
                            &tx,
                            &root.workspace_id,
                            parent_id,
                            Some(&root.id),
                        )?;
                    }
                }
                ensure_restore_destinations_available_in_tx(&tx, &roots)?;
            }

            let trashed_value = if action == FileStateAction::Trash {
                1_i64
            } else {
                0_i64
            };
            let trashed_at = (action == FileStateAction::Trash).then_some(updated_at.as_str());
            for file_id in &ids {
                tx.execute(
                    &format!(
                        "UPDATE files
                     SET revision = revision + 1,
                         trashed = ?1,
                         trashed_at = ?2,
                         updated_at = ?3
                     WHERE id = ?4{}",
                        if action == FileStateAction::Trash {
                            " AND trashed = 0"
                        } else {
                            ""
                        },
                    ),
                    params![trashed_value, trashed_at, &updated_at, file_id],
                )?;
            }
            if action == FileStateAction::Trash {
                let placeholders = std::iter::repeat_n("?", ids.len())
                    .collect::<Vec<_>>()
                    .join(", ");
                tx.execute(
                    &format!("DELETE FROM mobile_offline_files WHERE file_id IN ({placeholders})"),
                    params_from_iter(ids.iter()),
                )?;
            } else {
                for file_id in &ids {
                    let file = tx.query_row(
                        "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                                content_hash, created_at, updated_at, content_bytes, cover_hash
                         FROM files WHERE id = ?1 AND kind = 'file' AND trashed = 0",
                        params![file_id],
                        row_to_file,
                    ).optional()?;
                    if let Some(file) = file {
                        let _ = background_jobs::enqueue_file_background_jobs_in_tx(&tx, &file)?;
                    }
                }
            }
            insert_receipt_rows(&tx, receipt)?;
            tx.commit()?;
            root_ids
        };
        root_ids
            .iter()
            .map(|file_id| self.get_file(file_id)?.ok_or(ApiError::NotFound))
            .collect()
    }

    fn bulk_set_starred(
        &self,
        file_ids: &[String],
        action: FileStateAction,
        receipt: &Receipt,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<Vec<DriveFile>> {
        debug_assert!(!action.is_lifecycle());
        let updated_at = Utc::now().to_rfc3339();
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let files = file_ids
                .iter()
                .map(|file_id| {
                    tx.query_row(
                        "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                                content_hash, created_at, updated_at, content_bytes, cover_hash
                         FROM files WHERE id = ?1",
                        params![file_id],
                        row_to_file,
                    )
                    .optional()?
                    .ok_or(ApiError::NotFound)
                })
                .collect::<ApiResult<Vec<_>>>()?;
            if let Some((actor, source_credential)) = authorization_context {
                for file in &files {
                    ensure_file_state_action_authorized_in_tx(
                        &tx,
                        file,
                        action,
                        actor,
                        source_credential,
                    )?;
                }
            }
            let ids = files.iter().map(|file| file.id.clone()).collect::<Vec<_>>();
            validate_file_state_action_in_tx(&tx, &ids, action)?;

            let starred_value = if action == FileStateAction::Star {
                1_i64
            } else {
                0_i64
            };
            for file_id in &ids {
                tx.execute(
                    "UPDATE files SET starred = ?1, updated_at = ?2 WHERE id = ?3",
                    params![starred_value, &updated_at, file_id],
                )?;
            }
            insert_receipt_rows(&tx, receipt)?;
            tx.commit()?;
        }
        file_ids
            .iter()
            .map(|file_id| self.get_file(file_id)?.ok_or(ApiError::NotFound))
            .collect()
    }

    pub fn set_starred(&self, file_id: &str, starred: bool) -> ApiResult<(DriveFile, Receipt)> {
        self.set_starred_as(file_id, starred, "system")
    }

    pub fn set_starred_as(
        &self,
        file_id: &str,
        starred: bool,
        actor: &str,
    ) -> ApiResult<(DriveFile, Receipt)> {
        self.set_starred_inner(file_id, starred, actor, None)
    }

    pub(crate) fn set_starred_authorized(
        &self,
        file_id: &str,
        starred: bool,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DriveFile, Receipt)> {
        self.set_starred_inner(
            file_id,
            starred,
            &actor.email,
            Some((actor, source_credential)),
        )
    }

    fn set_starred_inner(
        &self,
        file_id: &str,
        starred: bool,
        receipt_actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(DriveFile, Receipt)> {
        let action = if starred {
            FileStateAction::Star
        } else {
            FileStateAction::Unstar
        };
        let updated_at = Utc::now().to_rfc3339();
        let receipt_kind = if starred { "file.star" } else { "file.unstar" };
        let receipt = new_receipt(receipt_kind, receipt_actor, Some(file_id));
        let file = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let file = tx
                .query_row(
                    "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                            content_hash, created_at, updated_at, content_bytes, cover_hash
                     FROM files WHERE id = ?1",
                    params![file_id],
                    row_to_file,
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if let Some((actor, source_credential)) = authorization_context {
                ensure_file_state_action_authorized_in_tx(
                    &tx,
                    &file,
                    action,
                    actor,
                    source_credential,
                )?;
            }
            validate_file_state_action_in_tx(&tx, std::slice::from_ref(&file.id), action)?;
            tx.execute(
                "UPDATE files SET starred = ?1, updated_at = ?2 WHERE id = ?3",
                params![if starred { 1 } else { 0 }, &updated_at, file_id],
            )?;
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
            file.id
        };
        let file = self.get_file(&file)?.ok_or(ApiError::NotFound)?;
        Ok((file, receipt))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileStateAction {
    Trash,
    Restore,
    Star,
    Unstar,
}

impl FileStateAction {
    fn parse(value: &str) -> ApiResult<Self> {
        match value {
            "trash" => Ok(Self::Trash),
            "restore" => Ok(Self::Restore),
            "star" => Ok(Self::Star),
            "unstar" => Ok(Self::Unstar),
            _ => Err(ApiError::Validation(
                "action must be trash, restore, star, or unstar".to_string(),
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Trash => "trash",
            Self::Restore => "restore",
            Self::Star => "star",
            Self::Unstar => "unstar",
        }
    }

    const fn is_lifecycle(self) -> bool {
        matches!(self, Self::Trash | Self::Restore)
    }

    const fn state_requirement(self) -> (&'static str, i64, &'static str) {
        match self {
            Self::Trash => ("trashed", 0, "live"),
            Self::Restore => ("trashed", 1, "in trash"),
            Self::Star => ("starred", 0, "unstarred"),
            Self::Unstar => ("starred", 1, "starred"),
        }
    }

    fn incompatible_state_error(self) -> ApiError {
        let (_, _, required_state) = self.state_requirement();
        ApiError::Validation(format!(
            "cannot {}: every selected item must be {required_state}",
            self.as_str()
        ))
    }
}

/// Item grants cover only the live file tree.  Every state action that targets
/// retained data, and every restore attempt, must therefore require a current
/// workspace-wide write grant in the same transaction that validates and
/// applies the transition.  This prevents a stale item grant from reviving or
/// otherwise modifying a trashed file while preserving item-scoped writes for
/// live trash/star actions.
fn ensure_file_state_action_authorized_in_tx(
    tx: &rusqlite::Transaction<'_>,
    file: &DriveFile,
    action: FileStateAction,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    if file.trashed || action == FileStateAction::Restore {
        authorization::ensure_workspace_authorized(
            tx,
            &file.workspace_id,
            actor,
            source_credential,
            WorkspacePermission::Write,
        )
    } else {
        ensure_item_authorized_in_tx(
            tx,
            &file.id,
            actor,
            source_credential,
            WorkspacePermission::Write,
        )
        .map(|_| ())
    }
}

fn validate_file_state_action_in_tx(
    tx: &rusqlite::Transaction<'_>,
    file_ids: &[String],
    action: FileStateAction,
) -> ApiResult<()> {
    if file_ids.is_empty() {
        return Err(ApiError::Validation("file_ids cannot be empty".to_string()));
    }
    let (column, expected_value, _) = action.state_requirement();
    let placeholders = std::iter::repeat_n("?", file_ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let mut values: Vec<&dyn ToSql> = vec![&expected_value];
    values.extend(file_ids.iter().map(|file_id| file_id as &dyn ToSql));
    let compatible: i64 = tx.query_row(
        &format!("SELECT COUNT(*) FROM files WHERE {column} = ?1 AND id IN ({placeholders})"),
        params_from_iter(values),
        |row| row.get(0),
    )?;
    if compatible != file_ids.len() as i64 {
        return Err(action.incompatible_state_error());
    }
    Ok(())
}

fn bulk_lifecycle_roots_in_tx(
    tx: &rusqlite::Transaction<'_>,
    file_ids: &[String],
) -> ApiResult<Vec<DriveFile>> {
    let selected = file_ids.iter().cloned().collect::<HashSet<_>>();
    let selected_files = file_ids
        .iter()
        .map(|file_id| {
            tx.query_row(
                "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                        content_hash, created_at, updated_at, content_bytes, cover_hash
                 FROM files WHERE id = ?1",
                params![file_id],
                row_to_file,
            )
            .optional()?
            .ok_or(ApiError::NotFound)
        })
        .collect::<ApiResult<Vec<_>>>()?;

    let mut roots = Vec::new();
    for file in selected_files {
        let mut parent_id = file.parent_id.clone();
        let mut visited = HashSet::new();
        let mut selected_ancestor = false;
        while let Some(parent) = parent_id {
            if !visited.insert(parent.clone()) {
                return Err(ApiError::Validation(
                    "file tree contains a parent cycle".to_string(),
                ));
            }
            if selected.contains(&parent) {
                selected_ancestor = true;
            }
            parent_id = tx
                .query_row(
                    "SELECT parent_id FROM files WHERE id = ?1",
                    params![&parent],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
        }
        if !selected_ancestor {
            roots.push(file);
        }
    }
    Ok(roots)
}
