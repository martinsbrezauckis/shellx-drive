use std::collections::BTreeSet;

use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection};

use crate::{
    auth::Actor,
    error::{ApiError, ApiResult},
    model::{
        DriveFile, SyncChange, SyncConflict, SyncHealthResponse, SyncHealthTotals,
        SyncWorkspaceHealth, Workspace,
    },
};

use super::{
    actor_scope::actor_workspace_scope, bounded_files::effectively_live_sql_predicate,
    files::attach_folder_sizes_complete_tree, row_to_file, row_to_sync_change,
    row_to_sync_conflict, Receipt, Storage,
};

const SYNC_CHANGE_PAGE_LIMIT: usize = 500;
const SYNC_CONFLICT_PAGE_LIMIT: usize = 500;
/// A destructive batch may invalidate a workspace manifest, but it must not
/// turn one operation into an unbounded number of cursor events. Emit at most
/// one durable rescan marker for each affected workspace.
const MAX_WORKSPACE_RESCAN_EVENTS_PER_MUTATION: usize = 1_000;

/// Read the replay cursor before selecting files. A mutation committed while
/// the manifest is being assembled must remain visible after this cursor, even
/// when the manifest did not select it. Replaying an already-selected change is
/// safe; advancing past an unselected change would lose it permanently.
pub(super) fn manifest_with_cursor(
    storage: &Storage,
    workspace_id: &str,
    read_files: impl FnOnce() -> ApiResult<Vec<DriveFile>>,
) -> ApiResult<(Vec<DriveFile>, i64)> {
    let next_cursor = storage.current_sync_cursor(workspace_id)?;
    let files = read_files()?;
    Ok((files, next_cursor))
}

/// Persist explicit workspace-rescan markers for a destructive operation.
///
/// The normal receipt mapper resolves file targets through live rows. That is
/// intentionally insufficient for a batch deletion because those rows no
/// longer exist after the mutation. Callers therefore capture and de-duplicate
/// affected workspaces before deleting anything, write the receipt first, and
/// then write one marker per workspace in the same transaction.
pub(super) fn insert_workspace_rescan_sync_changes(
    conn: &Connection,
    workspace_ids: &[String],
    receipt: &Receipt,
) -> ApiResult<()> {
    let workspace_ids = workspace_ids.iter().collect::<BTreeSet<_>>();
    if workspace_ids.len() > MAX_WORKSPACE_RESCAN_EVENTS_PER_MUTATION {
        return Err(ApiError::Validation(format!(
            "destructive batch affects more than {MAX_WORKSPACE_RESCAN_EVENTS_PER_MUTATION} workspaces"
        )));
    }
    for workspace_id in workspace_ids {
        conn.execute(
            "INSERT INTO sync_changes (
                workspace_id, kind, entity_type, entity_id, actor, receipt_id, created_at
             ) VALUES (?1, 'workspace.rescan', 'workspace', ?1, ?2, ?3, ?4)",
            params![
                workspace_id.as_str(),
                &receipt.actor,
                &receipt.id,
                &receipt.created_at,
            ],
        )?;
    }
    Ok(())
}

impl Storage {
    pub(crate) fn list_sync_manifest_files_with_cursor(
        &self,
        workspace_id: &str,
        max_rows: usize,
    ) -> ApiResult<(Vec<DriveFile>, i64)> {
        manifest_with_cursor(self, workspace_id, || {
            self.list_sync_manifest_files(workspace_id, max_rows)
        })
    }

    /// Materialize the active desktop manifest with an explicit server-side
    /// row ceiling. The sentinel row makes an oversized workspace fail before
    /// recursive folder-size derivation or JSON serialization begins.
    pub fn list_sync_manifest_files(
        &self,
        workspace_id: &str,
        max_rows: usize,
    ) -> ApiResult<Vec<DriveFile>> {
        let query_limit = i64::try_from(max_rows)
            .unwrap_or(i64::MAX)
            .saturating_add(1);
        let conn = self.conn.lock().unwrap();
        let effective_visibility = effectively_live_sql_predicate("files");
        let sql = format!(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                    content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files
             WHERE workspace_id = ?1 AND trashed = 0
               AND {effective_visibility}
             ORDER BY updated_at DESC, id DESC
             LIMIT ?2"
        );
        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map(params![workspace_id, query_limit], row_to_file)?;
        let mut files = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if files.len() > max_rows {
            return Err(ApiError::PayloadTooLarge(format!(
                "workspace sync manifest exceeds the {max_rows}-item limit"
            )));
        }
        // `files` is the complete, bounded effectively-live workspace tree.
        // Derive folder totals in memory so a deep legal tree cannot multiply
        // recursive SQLite work while this connection mutex is held.
        attach_folder_sizes_complete_tree(&mut files)?;
        Ok(files)
    }

    pub fn list_sync_changes_for_actor(
        &self,
        actor: &Actor,
        cursor: i64,
    ) -> ApiResult<Vec<SyncChange>> {
        let Some(scope) = actor_workspace_scope(actor) else {
            return Ok(Vec::new());
        };
        let cursor = cursor.max(0);
        let conn = self.conn.lock().unwrap();
        let floor_sql = format!(
            "WITH visible_workspaces AS ({})
             SELECT COALESCE(MAX(f.floor_cursor), 0)
             FROM sync_change_floors f
             JOIN visible_workspaces vw ON vw.id = f.workspace_id",
            scope.sql
        );
        let floor: i64 = conn.query_row(
            &floor_sql,
            params_from_iter(scope.parameters.iter()),
            |row| row.get(0),
        )?;
        if cursor < floor {
            return Err(ApiError::Conflict);
        }
        let cursor_parameter = scope.next_parameter;
        let limit_parameter = cursor_parameter + 1;
        let mut parameters = scope.parameters;
        parameters.push(SqlValue::Integer(cursor));
        parameters.push(SqlValue::Integer(
            i64::try_from(SYNC_CHANGE_PAGE_LIMIT).unwrap_or(i64::MAX),
        ));
        let sql = format!(
            "WITH visible_workspaces AS ({})
             SELECT sc.id, sc.workspace_id, sc.kind, sc.entity_type, sc.entity_id,
                    sc.actor, sc.receipt_id, sc.created_at
             FROM sync_changes sc
             JOIN visible_workspaces vw ON vw.id = sc.workspace_id
             WHERE sc.id > ?{cursor_parameter}
             ORDER BY sc.id ASC
             LIMIT ?{limit_parameter}",
            scope.sql
        );
        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(parameters.iter()), row_to_sync_change)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn current_sync_cursor(&self, workspace_id: &str) -> ApiResult<i64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row(
            "SELECT MAX(
                 COALESCE((SELECT MAX(id) FROM sync_changes WHERE workspace_id = ?1), 0),
                 COALESCE((SELECT floor_cursor FROM sync_change_floors WHERE workspace_id = ?1), 0)
             )",
            params![workspace_id],
            |row| row.get(0),
        )?)
    }

    pub fn list_sync_conflicts_for_actor(&self, actor: &Actor) -> ApiResult<Vec<SyncConflict>> {
        let Some(scope) = actor_workspace_scope(actor) else {
            return Ok(Vec::new());
        };
        let limit_parameter = scope.next_parameter;
        let mut parameters = scope.parameters;
        parameters.push(SqlValue::Integer(
            i64::try_from(SYNC_CONFLICT_PAGE_LIMIT).unwrap_or(i64::MAX),
        ));
        let effective_visibility = effectively_live_sql_predicate("f");
        let sql = format!(
            "WITH visible_workspaces AS ({})
             SELECT f.workspace_id, f.id, fr.conflict_of_file_id, f.name,
                    fr.conflict_of_revision, fr.created_at
             FROM file_revisions fr
             JOIN files f ON f.id = fr.file_id
             JOIN visible_workspaces vw ON vw.id = f.workspace_id
             WHERE fr.conflict_of_revision IS NOT NULL
               AND fr.conflict_of_file_id IS NOT NULL
               AND f.trashed = 0
               AND {effective_visibility}
             ORDER BY fr.created_at DESC, f.id DESC
             LIMIT ?{limit_parameter}",
            scope.sql
        );
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(&sql)?;
        let rows =
            statement.query_map(params_from_iter(parameters.iter()), row_to_sync_conflict)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn sync_health_for_workspaces(
        &self,
        workspaces: Vec<Workspace>,
        actor: Option<String>,
    ) -> ApiResult<SyncHealthResponse> {
        let mut totals = SyncHealthTotals {
            workspaces: workspaces.len() as i64,
            files: 0,
            folders: 0,
            trashed_files: 0,
            downloadable_files: 0,
        };
        let conn = self.conn.lock().unwrap();
        let effective_visibility = effectively_live_sql_predicate("files");
        let sql = format!(
            "WITH workspace_files AS (
                 SELECT files.*,
                        {effective_visibility} AS effectively_live
                 FROM files
                 WHERE workspace_id = ?1
             )
             SELECT
                COALESCE(SUM(CASE WHEN effectively_live AND kind = 'file' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN effectively_live AND kind = 'folder' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN trashed = 1 THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN effectively_live AND kind = 'file'
                                   AND content_hash IS NOT NULL THEN 1 ELSE 0 END), 0),
                MAX(CASE WHEN effectively_live THEN updated_at END)
             FROM workspace_files"
        );
        let mut statement = conn.prepare(&sql)?;
        let mut rows = Vec::with_capacity(workspaces.len());
        for workspace in workspaces {
            let (files, folders, trashed_files, downloadable_files, last_updated_at) = statement
                .query_row(params![&workspace.id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                })?;
            totals.files += files;
            totals.folders += folders;
            totals.trashed_files += trashed_files;
            totals.downloadable_files += downloadable_files;
            rows.push(SyncWorkspaceHealth {
                workspace_id: workspace.id,
                name: workspace.name,
                storage_mode: workspace.storage_mode,
                files,
                folders,
                trashed_files,
                downloadable_files,
                last_updated_at,
            });
        }
        Ok(SyncHealthResponse {
            mode: "sync_health".to_string(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            actor,
            totals,
            workspaces: rows,
        })
    }
}

#[cfg(test)]
mod tests;
