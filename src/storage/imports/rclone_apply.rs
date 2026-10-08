use chrono::Utc;
use rusqlite::{params, OptionalExtension, Transaction};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{
        DriveFile, FileKind, RcloneFolderCollisionPolicy, RcloneImportPreviewAction,
        RcloneImportSummary, Receipt,
    },
};

use super::super::{
    bounded_files::ensure_workspace_node_capacity, record_sync_change_for_receipt,
    refresh_file_search_index_locked, retained_revision_quota_bytes,
};
use super::Storage;

mod planning;
use planning::plan_rclone_import;

#[derive(Debug, Clone)]
pub(crate) struct PreparedRcloneContent {
    pub(crate) hash: String,
    pub(crate) text: String,
    pub(crate) bytes: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedRcloneEntry {
    pub(crate) parts: Vec<String>,
    pub(crate) kind: FileKind,
    pub(crate) content: Option<PreparedRcloneContent>,
}

#[derive(Debug)]
pub(crate) struct AtomicRcloneImport {
    pub(crate) imported: Vec<DriveFile>,
    pub(crate) summary: RcloneImportSummary,
    pub(crate) actions: Vec<RcloneImportPreviewAction>,
    pub(crate) receipt: Receipt,
}

#[derive(Debug)]
pub(crate) struct RcloneImportPreview {
    pub(crate) summary: RcloneImportSummary,
    pub(crate) actions: Vec<RcloneImportPreviewAction>,
}

pub(super) enum Mutation {
    Create {
        file: DriveFile,
    },
    Update {
        file: DriveFile,
        content: PreparedRcloneContent,
    },
}

pub(super) struct PlannedRcloneImport {
    mutations: Vec<Mutation>,
    imported: Vec<DriveFile>,
    summary: RcloneImportSummary,
    actions: Vec<RcloneImportPreviewAction>,
}

impl Storage {
    /// Apply a complete rclone-v1 bundle in one immediate SQLite transaction.
    /// Path resolution, collision checks, aggregate quota admission, revisions,
    /// search indexes, the receipt, activity, and sync cursor publication all
    /// either commit together or leave the workspace unchanged.
    pub(crate) fn apply_rclone_import_atomic(
        &self,
        workspace_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
        entries: Vec<PreparedRcloneEntry>,
        folder_collision_policy: RcloneFolderCollisionPolicy,
    ) -> ApiResult<AtomicRcloneImport> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        crate::storage::authorization::ensure_workspace_authorized(
            &tx,
            workspace_id,
            actor,
            source_credential,
            WorkspacePermission::Write,
        )?;
        tx.query_row(
            "SELECT storage_mode FROM workspaces WHERE id = ?1",
            params![workspace_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(ApiError::NotFound)?;

        let now = Utc::now().to_rfc3339();
        let plan = plan_rclone_import(&tx, workspace_id, entries, folder_collision_policy, &now)?;

        let created_nodes = plan
            .mutations
            .iter()
            .filter(|mutation| matches!(mutation, Mutation::Create { .. }))
            .count();
        ensure_workspace_node_capacity(&tx, workspace_id, created_nodes)?;
        enforce_aggregate_quota(&tx, workspace_id, &plan.mutations)?;
        for mutation in &plan.mutations {
            apply_mutation(&tx, mutation, &now)?;
        }

        let receipt = Receipt {
            id: Uuid::now_v7().to_string(),
            kind: "import.apply".to_string(),
            actor: actor.email.clone(),
            target_id: Some(workspace_id.to_string()),
            created_at: now.clone(),
        };
        tx.execute(
            "INSERT INTO receipts (id, kind, actor, target_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &receipt.id,
                &receipt.kind,
                &receipt.actor,
                &receipt.target_id,
                &receipt.created_at
            ],
        )?;
        tx.execute(
            "INSERT INTO activity (id, kind, actor, target_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                Uuid::now_v7().to_string(),
                &receipt.kind,
                &receipt.actor,
                &receipt.target_id,
                &receipt.created_at
            ],
        )?;
        record_sync_change_for_receipt(&tx, &receipt)?;

        tx.commit()?;

        Ok(AtomicRcloneImport {
            imported: plan.imported,
            summary: plan.summary,
            actions: plan.actions,
            receipt,
        })
    }

    /// Preview and apply call the exact same virtual-tree planner. The preview
    /// intentionally remains advisory across later concurrent mutations, but
    /// its collision and path decisions match an apply against this snapshot.
    pub(crate) fn preview_rclone_import(
        &self,
        workspace_id: &str,
        entries: Vec<PreparedRcloneEntry>,
        folder_collision_policy: RcloneFolderCollisionPolicy,
    ) -> ApiResult<RcloneImportPreview> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        tx.query_row(
            "SELECT storage_mode FROM workspaces WHERE id = ?1",
            params![workspace_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(ApiError::NotFound)?;
        let plan = plan_rclone_import(
            &tx,
            workspace_id,
            entries,
            folder_collision_policy,
            &Utc::now().to_rfc3339(),
        )?;
        Ok(RcloneImportPreview {
            summary: plan.summary,
            actions: plan.actions,
        })
    }
}

fn enforce_aggregate_quota(
    tx: &Transaction<'_>,
    workspace_id: &str,
    mutations: &[Mutation],
) -> ApiResult<()> {
    let quota = tx
        .query_row(
            "SELECT quota_bytes FROM workspace_policies WHERE workspace_id = ?1",
            params![workspace_id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten();
    let Some(quota) = quota else {
        return Ok(());
    };
    let current: i64 = tx.query_row(
        "SELECT COALESCE(SUM(
                CASE WHEN content_bytes > 0 THEN content_bytes ELSE 1 END
                + CASE WHEN cover_bytes > 0 THEN cover_bytes ELSE 0 END
            ), 0)
         FROM files WHERE workspace_id = ?1",
        params![workspace_id],
        |row| row.get(0),
    )?;
    let retained = retained_revision_quota_bytes(tx, workspace_id)?;
    let mut projected = current
        .checked_add(retained)
        .ok_or_else(|| ApiError::Validation("rclone quota projection overflow".to_string()))?;
    for mutation in mutations {
        // Existing current bodies remain charged because an update turns them
        // into retained history. Covers are already present in `current` and
        // are unchanged by rclone body replacement, so only the new body is an
        // additional charge.
        let delta = match mutation {
            Mutation::Create { file, .. } => file.size_bytes.unwrap_or(0).max(1),
            Mutation::Update { content, .. } => content.bytes.max(1),
        };
        projected = projected
            .checked_add(delta)
            .ok_or_else(|| ApiError::Validation("rclone quota projection overflow".to_string()))?;
    }
    if projected > quota {
        return Err(ApiError::Validation(format!(
            "quota exceeded: {projected} bytes would exceed workspace quota {quota} bytes"
        )));
    }
    Ok(())
}

fn apply_mutation(tx: &Transaction<'_>, mutation: &Mutation, now: &str) -> ApiResult<()> {
    let file = match mutation {
        Mutation::Create { file } => {
            let content_bytes = file.size_bytes.unwrap_or(0);
            tx.execute(
                "INSERT INTO files (id, workspace_id, parent_id, name, kind, revision,
                    trashed, starred, content_hash, content_bytes, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, 0, 0, ?6, ?7, ?8, ?8)",
                params![
                    &file.id,
                    &file.workspace_id,
                    &file.parent_id,
                    &file.name,
                    file.kind.as_db_str(),
                    &file.content_hash,
                    content_bytes,
                    now
                ],
            )?;
            tx.execute(
                "INSERT INTO file_revisions
                    (id, file_id, revision, content_hash, content_bytes, created_at, conflict_of_revision)
                 VALUES (?1, ?2, 1, ?3, ?4, ?5, NULL)",
                params![
                    Uuid::now_v7().to_string(),
                    &file.id,
                    &file.content_hash,
                    content_bytes,
                    now
                ],
            )?;
            file
        }
        Mutation::Update { file, content } => {
            tx.execute(
                "UPDATE files SET revision = ?1, content_hash = ?2, content_bytes = ?3,
                    updated_at = ?4 WHERE id = ?5 AND workspace_id = ?6 AND trashed = 0",
                params![
                    file.revision,
                    &content.hash,
                    content.bytes,
                    now,
                    &file.id,
                    &file.workspace_id
                ],
            )?;
            tx.execute(
                "INSERT INTO file_revisions
                    (id, file_id, revision, content_hash, content_bytes, created_at, conflict_of_revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                params![
                    Uuid::now_v7().to_string(),
                    &file.id,
                    file.revision,
                    &content.hash,
                    content.bytes,
                    now
                ],
            )?;
            file
        }
    };

    refresh_file_search_index_locked(tx, &file.id)?;
    if matches!(file.kind, FileKind::File) {
        let _ = super::super::background_jobs::enqueue_file_background_jobs_in_tx(tx, file)?;
    }
    Ok(())
}
