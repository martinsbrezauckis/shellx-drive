use std::collections::HashMap;

use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind, Receipt},
};

use super::{
    insert_receipt_rows,
    validation::{normalize_template_path, validate_prepared_template_items},
    PreparedFolderTemplateItem, MAX_FOLDER_TEMPLATE_ITEMS,
};
use crate::storage::{
    authorization, bounded_files::ensure_workspace_node_capacity, enforce_quota_charge_in_txn,
    refresh_file_search_index_locked, validate_file_name, Storage, MAX_FILE_TREE_NODES,
};

struct PlannedTemplateFile {
    file: DriveFile,
}

impl Storage {
    pub(crate) fn apply_folder_template_authorized(
        &self,
        workspace_id: &str,
        template_id: &str,
        root_name: &str,
        items: Vec<PreparedFolderTemplateItem>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(Vec<DriveFile>, Receipt)> {
        self.apply_folder_template_inner(
            workspace_id,
            template_id,
            root_name,
            items,
            &actor.email,
            Some((actor, source_credential)),
        )
    }

    fn apply_folder_template_inner(
        &self,
        workspace_id: &str,
        template_id: &str,
        root_name: &str,
        items: Vec<PreparedFolderTemplateItem>,
        actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(Vec<DriveFile>, Receipt)> {
        let root_name = validate_file_name(root_name)?;
        if items.is_empty() || items.len() > MAX_FOLDER_TEMPLATE_ITEMS {
            return Err(ApiError::PayloadTooLarge(format!(
                "folder templates must contain 1 to {MAX_FOLDER_TEMPLATE_ITEMS} items"
            )));
        }
        validate_prepared_template_items(&items)?;
        let now = Utc::now().to_rfc3339();
        let mut planned = plan_template_files(workspace_id, &root_name, items, &now)?;
        let additional_quota_bytes = planned.iter().try_fold(0_i64, |total, planned| {
            total
                .checked_add(planned.file.size_bytes.unwrap_or(0).max(1))
                .ok_or_else(|| ApiError::Validation("folder template quota overflow".to_string()))
        })?;
        let receipt = Receipt {
            id: Uuid::now_v7().to_string(),
            kind: "folder_template.apply".to_string(),
            actor: actor.to_string(),
            target_id: Some(template_id.to_string()),
            created_at: now.clone(),
        };

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((actor, source_credential)) = authorization_context {
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
        }
        let template_exists: bool = tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM folder_templates WHERE id = ?1 AND workspace_id = ?2
             )",
            params![template_id, workspace_id],
            |row| row.get(0),
        )?;
        if !template_exists {
            return Err(ApiError::NotFound);
        }
        let available_root_name = crate::storage::file_destination::available_copy_name_in_tx(
            &tx,
            workspace_id,
            None,
            &planned[0].file.name,
        )?;
        planned[0].file.name = available_root_name;
        ensure_workspace_node_capacity(&tx, workspace_id, planned.len())?;
        let quota_bytes = tx
            .query_row(
                "SELECT quota_bytes FROM workspace_policies WHERE workspace_id = ?1",
                params![workspace_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten();
        if let Some(quota_bytes) = quota_bytes {
            enforce_quota_charge_in_txn(
                &tx,
                quota_bytes,
                workspace_id,
                None,
                additional_quota_bytes,
            )?;
        }

        for planned_file in &planned {
            insert_planned_file(&tx, planned_file)?;
        }
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((
            planned.into_iter().map(|planned| planned.file).collect(),
            receipt,
        ))
    }
}

fn insert_planned_file(
    tx: &rusqlite::Transaction<'_>,
    planned: &PlannedTemplateFile,
) -> ApiResult<()> {
    let file = &planned.file;
    let content_bytes = file.size_bytes.unwrap_or(0);
    tx.execute(
        "INSERT INTO files (
            id, workspace_id, parent_id, name, kind, revision, trashed, starred,
            content_hash, content_bytes, created_at, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 0, 0, ?6, ?7, ?8, ?8)",
        params![
            &file.id,
            &file.workspace_id,
            &file.parent_id,
            &file.name,
            file.kind.as_db_str(),
            &file.content_hash,
            content_bytes,
            &file.created_at,
        ],
    )?;
    tx.execute(
        "INSERT INTO file_revisions (
            id, file_id, revision, content_hash, content_bytes, created_at,
            conflict_of_revision
         ) VALUES (?1, ?2, 1, ?3, ?4, ?5, NULL)",
        params![
            Uuid::now_v7().to_string(),
            &file.id,
            &file.content_hash,
            content_bytes,
            &file.created_at,
        ],
    )?;
    refresh_file_search_index_locked(tx, &file.id)?;
    let _ = crate::storage::background_jobs::enqueue_file_background_jobs_in_tx(tx, file)?;
    Ok(())
}

fn plan_template_files(
    workspace_id: &str,
    root_name: &str,
    items: Vec<PreparedFolderTemplateItem>,
    now: &str,
) -> ApiResult<Vec<PlannedTemplateFile>> {
    let root = new_planned_file(workspace_id, None, root_name, FileKind::Folder, now);
    let mut planned = vec![PlannedTemplateFile { file: root.clone() }];
    let mut folder_ids = HashMap::from([(String::new(), root.id)]);

    for item in items {
        let path = normalize_template_path(&item.path)?;
        if matches!(item.kind, FileKind::Folder)
            && (item.content_hash.is_some()
                || item.content_text.is_some()
                || item.content_bytes != 0)
        {
            return Err(ApiError::Validation(
                "folder template folders cannot contain file content".to_string(),
            ));
        }
        let parts = path.split('/').collect::<Vec<_>>();
        let folder_part_count = if matches!(item.kind, FileKind::Folder) {
            parts.len()
        } else {
            parts.len() - 1
        };
        let mut parent_id = folder_ids[""].clone();
        let mut folder_path = String::new();
        for part in parts.iter().take(folder_part_count) {
            if !folder_path.is_empty() {
                folder_path.push('/');
            }
            folder_path.push_str(part);
            if let Some(existing_id) = folder_ids.get(&folder_path) {
                parent_id = existing_id.clone();
                continue;
            }
            let folder =
                new_planned_file(workspace_id, Some(parent_id), part, FileKind::Folder, now);
            parent_id = folder.id.clone();
            folder_ids.insert(folder_path.clone(), folder.id.clone());
            push_planned_file(&mut planned, PlannedTemplateFile { file: folder })?;
        }
        if matches!(item.kind, FileKind::Folder) {
            continue;
        }
        let name = parts.last().ok_or_else(|| {
            ApiError::Validation("template file path must contain a name".to_string())
        })?;
        let mut file = new_planned_file(workspace_id, Some(parent_id), name, FileKind::File, now);
        file.content_hash = item.content_hash;
        file.size_bytes = Some(item.content_bytes);
        push_planned_file(&mut planned, PlannedTemplateFile { file })?;
    }
    Ok(planned)
}

fn push_planned_file(
    planned: &mut Vec<PlannedTemplateFile>,
    file: PlannedTemplateFile,
) -> ApiResult<()> {
    if planned.len() >= MAX_FILE_TREE_NODES {
        return Err(ApiError::PayloadTooLarge(format!(
            "folder template expands beyond the {MAX_FILE_TREE_NODES}-item tree limit"
        )));
    }
    planned.push(file);
    Ok(())
}

fn new_planned_file(
    workspace_id: &str,
    parent_id: Option<String>,
    name: &str,
    kind: FileKind,
    now: &str,
) -> DriveFile {
    DriveFile {
        id: Uuid::now_v7().to_string(),
        workspace_id: workspace_id.to_string(),
        parent_id,
        name: name.to_string(),
        kind: kind.clone(),
        revision: 1,
        trashed: false,
        starred: false,
        content_hash: None,
        created_at: now.to_string(),
        updated_at: now.to_string(),
        size_bytes: matches!(kind, FileKind::File).then_some(0),
        folder_size_bytes: None,
        has_cover: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implicit_ancestor_expansion_is_bounded_before_storage() {
        let suffix = std::iter::repeat_n("a", 254).collect::<Vec<_>>().join("/");
        let items = (0..40)
            .map(|index| PreparedFolderTemplateItem {
                path: format!("branch-{index}/{suffix}"),
                kind: FileKind::Folder,
                content_hash: None,
                content_bytes: 0,
                content_text: None,
            })
            .collect();
        assert!(matches!(
            plan_template_files("workspace", "root", items, "now"),
            Err(ApiError::PayloadTooLarge(message)) if message.contains("expands beyond")
        ));
    }
}
