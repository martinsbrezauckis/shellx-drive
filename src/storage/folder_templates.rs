mod apply;
mod validation;

use std::collections::HashMap;

use chrono::Utc;
use rusqlite::{params, params_from_iter, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{
        CreateFolderTemplateItemRequest, FileKind, FolderTemplate, FolderTemplateItem, Receipt,
    },
};

use super::{
    authorization, record_sync_change_for_receipt, row_to_folder_template_base,
    row_to_folder_template_item, validate_file_name, Storage,
};
use validation::{normalize_description, normalize_template_items, template_content_bytes};

pub(crate) const MAX_FOLDER_TEMPLATES_PER_WORKSPACE: usize = 100;
pub(crate) const MAX_FOLDER_TEMPLATE_ITEMS: usize = 256;
pub(crate) const MAX_FOLDER_TEMPLATE_CONTENT_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_WORKSPACE_FOLDER_TEMPLATE_CONTENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_FOLDER_TEMPLATE_DESCRIPTION_BYTES: usize = 2_000;
const MAX_FOLDER_TEMPLATE_PATH_BYTES: usize = 1_024;
const MAX_DEBUG_FOLDER_TEMPLATES: usize = 1_000;
const MAX_FOLDER_TEMPLATE_RESPONSE_CONTENT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct PreparedFolderTemplateItem {
    pub path: String,
    pub kind: FileKind,
    pub content_hash: Option<String>,
    pub content_bytes: i64,
    pub content_text: Option<String>,
}

impl Storage {
    pub fn create_folder_template(
        &self,
        workspace_id: &str,
        created_by: &str,
        name: &str,
        description: Option<String>,
        items: Vec<CreateFolderTemplateItemRequest>,
    ) -> ApiResult<(FolderTemplate, Receipt)> {
        self.create_folder_template_inner(workspace_id, created_by, name, description, items, None)
    }

    pub(crate) fn create_folder_template_authorized(
        &self,
        workspace_id: &str,
        name: &str,
        description: Option<String>,
        items: Vec<CreateFolderTemplateItemRequest>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(FolderTemplate, Receipt)> {
        self.create_folder_template_inner(
            workspace_id,
            &actor.email,
            name,
            description,
            items,
            Some((actor, source_credential)),
        )
    }

    fn create_folder_template_inner(
        &self,
        workspace_id: &str,
        created_by: &str,
        name: &str,
        description: Option<String>,
        items: Vec<CreateFolderTemplateItemRequest>,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(FolderTemplate, Receipt)> {
        self.workspace_storage_mode(workspace_id)?;
        let name = validate_file_name(name)?;
        let description = normalize_description(description)?;
        let items = normalize_template_items(items)?;
        let content_bytes = template_content_bytes(&items)?;
        let now = Utc::now().to_rfc3339();
        let template_id = Uuid::now_v7().to_string();
        let mut stored_items = Vec::with_capacity(items.len());
        let receipt = Receipt {
            id: Uuid::now_v7().to_string(),
            kind: "folder_template.create".to_string(),
            actor: created_by.to_string(),
            target_id: Some(template_id.clone()),
            created_at: now.clone(),
        };

        {
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
            let template_count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM folder_templates WHERE workspace_id = ?1",
                params![workspace_id],
                |row| row.get(0),
            )?;
            if template_count >= MAX_FOLDER_TEMPLATES_PER_WORKSPACE as i64 {
                return Err(ApiError::PayloadTooLarge(format!(
                    "workspace folder templates are limited to {MAX_FOLDER_TEMPLATES_PER_WORKSPACE}"
                )));
            }
            let workspace_content_bytes: i64 = tx.query_row(
                "SELECT COALESCE(SUM(LENGTH(CAST(fti.content AS BLOB))), 0)
                 FROM folder_template_items fti
                 JOIN folder_templates ft ON ft.id = fti.template_id
                 WHERE ft.workspace_id = ?1",
                params![workspace_id],
                |row| row.get(0),
            )?;
            let projected_content_bytes = workspace_content_bytes
                .checked_add(content_bytes as i64)
                .ok_or_else(|| {
                    ApiError::PayloadTooLarge("folder template content size overflow".to_string())
                })?;
            if projected_content_bytes > MAX_WORKSPACE_FOLDER_TEMPLATE_CONTENT_BYTES as i64 {
                return Err(ApiError::PayloadTooLarge(format!(
                    "workspace folder template content is limited to {MAX_WORKSPACE_FOLDER_TEMPLATE_CONTENT_BYTES} bytes"
                )));
            }

            tx.execute(
                "INSERT INTO folder_templates (id, workspace_id, name, description, created_by, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    &template_id,
                    workspace_id,
                    &name,
                    &description,
                    created_by,
                    &now,
                ],
            )?;
            for item in items {
                let stored = FolderTemplateItem {
                    id: Uuid::now_v7().to_string(),
                    template_id: template_id.clone(),
                    path: item.path,
                    kind: item.kind,
                    content: item.content,
                    created_at: now.clone(),
                };
                tx.execute(
                    "INSERT INTO folder_template_items (id, template_id, path, kind, content, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        &stored.id,
                        &stored.template_id,
                        &stored.path,
                        stored.kind.as_db_str(),
                        &stored.content,
                        &stored.created_at,
                    ],
                )?;
                stored_items.push(stored);
            }
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
        }

        Ok((
            FolderTemplate {
                id: template_id,
                workspace_id: workspace_id.to_string(),
                name,
                description,
                created_by: created_by.to_string(),
                created_at: now,
                items: stored_items,
            },
            receipt,
        ))
    }

    pub fn list_folder_templates_for_workspace(
        &self,
        workspace_id: &str,
    ) -> ApiResult<Vec<FolderTemplate>> {
        self.workspace_storage_mode(workspace_id)?;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, name, description, created_by, created_at
             FROM folder_templates WHERE workspace_id = ?1 ORDER BY created_at ASC, id ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![
                workspace_id,
                (MAX_FOLDER_TEMPLATES_PER_WORKSPACE + 1) as i64
            ],
            row_to_folder_template_base,
        )?;
        let templates = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if templates.len() > MAX_FOLDER_TEMPLATES_PER_WORKSPACE {
            return Err(ApiError::PayloadTooLarge(
                "workspace folder template list exceeds its bounded limit".to_string(),
            ));
        }
        attach_folder_template_items(&conn, templates)
    }

    pub fn get_folder_template(&self, template_id: &str) -> ApiResult<Option<FolderTemplate>> {
        let conn = self.conn.lock().unwrap();
        let template = conn
            .query_row(
                "SELECT id, workspace_id, name, description, created_by, created_at
                 FROM folder_templates WHERE id = ?1",
                params![template_id],
                row_to_folder_template_base,
            )
            .optional()?;
        match template {
            Some(template) => Ok(attach_folder_template_items(&conn, vec![template])?
                .into_iter()
                .next()),
            None => Ok(None),
        }
    }

    pub fn list_all_folder_templates(&self) -> ApiResult<Vec<FolderTemplate>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, name, description, created_by, created_at
             FROM folder_templates ORDER BY created_at ASC, id ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(
            [(MAX_DEBUG_FOLDER_TEMPLATES + 1) as i64],
            row_to_folder_template_base,
        )?;
        let templates = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if templates.len() > MAX_DEBUG_FOLDER_TEMPLATES {
            return Err(ApiError::PayloadTooLarge(
                "debug folder template export exceeds its bounded limit".to_string(),
            ));
        }
        attach_folder_template_items(&conn, templates)
    }

    pub fn delete_folder_template(
        &self,
        workspace_id: &str,
        template_id: &str,
        actor: &str,
    ) -> ApiResult<Receipt> {
        self.delete_folder_template_inner(workspace_id, template_id, actor, None)
    }

    pub(crate) fn delete_folder_template_authorized(
        &self,
        workspace_id: &str,
        template_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        self.delete_folder_template_inner(
            workspace_id,
            template_id,
            &actor.email,
            Some((actor, source_credential)),
        )
    }

    fn delete_folder_template_inner(
        &self,
        workspace_id: &str,
        template_id: &str,
        actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<Receipt> {
        let now = Utc::now().to_rfc3339();
        let receipt = Receipt {
            id: Uuid::now_v7().to_string(),
            kind: "folder_template.delete".to_string(),
            actor: actor.to_string(),
            target_id: Some(template_id.to_string()),
            created_at: now,
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
        if tx.execute(
            "DELETE FROM folder_templates WHERE id = ?1 AND workspace_id = ?2",
            params![template_id, workspace_id],
        )? != 1
        {
            return Err(ApiError::NotFound);
        }
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }
}

fn attach_folder_template_items(
    conn: &rusqlite::Connection,
    mut templates: Vec<FolderTemplate>,
) -> ApiResult<Vec<FolderTemplate>> {
    if templates.is_empty() {
        return Ok(templates);
    }
    let by_id = templates
        .iter()
        .enumerate()
        .map(|(index, template)| (template.id.clone(), index))
        .collect::<HashMap<_, _>>();
    let placeholders = std::iter::repeat_n("?", templates.len())
        .collect::<Vec<_>>()
        .join(", ");
    let mut stmt = conn.prepare(&format!(
        "SELECT id, template_id, path, kind, content, created_at
         FROM folder_template_items
         WHERE template_id IN ({placeholders})
         ORDER BY template_id ASC, path ASC, id ASC"
    ))?;
    let rows = stmt.query_map(params_from_iter(by_id.keys()), row_to_folder_template_item)?;
    let mut response_content_bytes = 0_usize;
    let mut template_content_bytes = vec![0_usize; templates.len()];
    for item in rows {
        let item = item?;
        response_content_bytes = response_content_bytes
            .checked_add(item.content.as_ref().map_or(0, String::len))
            .ok_or_else(|| {
                ApiError::PayloadTooLarge("folder template response size overflow".to_string())
            })?;
        if response_content_bytes > MAX_FOLDER_TEMPLATE_RESPONSE_CONTENT_BYTES {
            return Err(ApiError::PayloadTooLarge(format!(
                "folder template response content is limited to {MAX_FOLDER_TEMPLATE_RESPONSE_CONTENT_BYTES} bytes"
            )));
        }
        let index = *by_id.get(&item.template_id).ok_or_else(|| {
            ApiError::Validation("folder template item references an unknown template".to_string())
        })?;
        template_content_bytes[index] = template_content_bytes[index]
            .checked_add(item.content.as_ref().map_or(0, String::len))
            .ok_or_else(|| {
                ApiError::PayloadTooLarge("folder template content size overflow".to_string())
            })?;
        if template_content_bytes[index] > MAX_FOLDER_TEMPLATE_CONTENT_BYTES {
            return Err(ApiError::PayloadTooLarge(format!(
                "folder template embedded content is limited to {MAX_FOLDER_TEMPLATE_CONTENT_BYTES} bytes"
            )));
        }
        if templates[index].items.len() >= MAX_FOLDER_TEMPLATE_ITEMS {
            return Err(ApiError::PayloadTooLarge(
                "folder template item list exceeds its bounded limit".to_string(),
            ));
        }
        templates[index].items.push(item);
    }
    Ok(templates)
}

pub(super) fn insert_receipt_rows(
    tx: &rusqlite::Transaction<'_>,
    receipt: &Receipt,
) -> ApiResult<()> {
    tx.execute(
        "INSERT INTO receipts (id, kind, actor, target_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            &receipt.id,
            &receipt.kind,
            &receipt.actor,
            &receipt.target_id,
            &receipt.created_at,
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
            &receipt.created_at,
        ],
    )?;
    record_sync_change_for_receipt(tx, receipt)?;
    Ok(())
}
