use std::collections::{BTreeSet, HashMap};

use rusqlite::{params, params_from_iter, types::Value as SqlValue};

use crate::{
    auth::Actor,
    error::ApiResult,
    model::{Activity, DriveFile, SearchResult},
};

use super::{
    actor_scope::actor_workspace_scope, bounded_files::effectively_live_sql_predicate,
    files::attach_folder_sizes_locked,
    human_item_grants::actor_visibility::actor_file_visibility_scope, normalize_fts_query,
    row_to_file, Storage, MAX_COMPATIBILITY_FILE_LIST,
};

const SEARCH_RESULT_LIMIT: usize = 100;
const ALTERNATE_FILE_LIST_LIMIT: usize = 500;
const ACTIVITY_PAGE_LIMIT: usize = 500;

pub(crate) struct ActivityPublicationSubjects {
    pub workspace_ids: Vec<String>,
    pub file_ids: Vec<String>,
}

impl Storage {
    pub fn search_files(&self, query: &str) -> ApiResult<Vec<DriveFile>> {
        Ok(self
            .search_file_results(query)?
            .into_iter()
            .map(|result| result.file)
            .collect())
    }

    /// Admin/debug search remains global, but it is a fixed-size diagnostic
    /// page rather than an unbounded product query.
    pub fn search_file_results(&self, query: &str) -> ApiResult<Vec<SearchResult>> {
        let Some(fts_query) = normalize_fts_query(query)? else {
            return Ok(Vec::new());
        };
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(&format!(
            "{SEARCH_SELECT}
             WHERE files.trashed = 0 AND file_search_fts MATCH ?1
             ORDER BY rank ASC, files.updated_at DESC
             LIMIT ?2"
        ))?;
        let rows = statement.query_map(
            params![
                fts_query,
                i64::try_from(SEARCH_RESULT_LIMIT).unwrap_or(i64::MAX)
            ],
            row_to_search_result,
        )?;
        let mut results = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        attach_result_folder_sizes_if_bounded(&conn, &mut results)?;
        Ok(results)
    }

    pub fn search_file_results_for_actor(
        &self,
        actor: &Actor,
        query: &str,
    ) -> ApiResult<Vec<SearchResult>> {
        Ok(self.search_file_results_for_actor_page(actor, query)?.0)
    }

    pub fn search_file_results_for_actor_page(
        &self,
        actor: &Actor,
        query: &str,
    ) -> ApiResult<(Vec<SearchResult>, bool)> {
        let Some(fts_query) = normalize_fts_query(query)? else {
            return Ok((Vec::new(), false));
        };
        let Some(scope) = actor_file_visibility_scope(actor) else {
            return Ok((Vec::new(), false));
        };
        let fts_parameter = scope.next_parameter;
        let limit_parameter = fts_parameter + 1;
        let visible_file = scope.visible_file_predicate("files");
        let mut parameters = scope.parameters;
        parameters.push(SqlValue::Text(fts_query));
        parameters.push(SqlValue::Integer(
            i64::try_from(SEARCH_RESULT_LIMIT + 1).unwrap_or(i64::MAX),
        ));
        let effective_visibility = effectively_live_sql_predicate("files");
        let sql = format!(
            "WITH RECURSIVE {}
             {SEARCH_SELECT}
             WHERE files.trashed = 0 AND file_search_fts MATCH ?{fts_parameter}
               AND {effective_visibility}
               AND {visible_file}
             ORDER BY rank ASC, files.updated_at DESC
             LIMIT ?{limit_parameter}",
            scope.cte_sql
        );
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(&sql)?;
        let rows =
            statement.query_map(params_from_iter(parameters.iter()), row_to_search_result)?;
        let mut results = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let has_more = results.len() > SEARCH_RESULT_LIMIT;
        results.truncate(SEARCH_RESULT_LIMIT);
        attach_result_folder_sizes_if_bounded(&conn, &mut results)?;
        Ok((results, has_more))
    }

    pub fn recent_files_for_actor(&self, actor: &Actor) -> ApiResult<Vec<DriveFile>> {
        actor_file_page(self, actor, "1 = 1", "f.updated_at DESC, f.id DESC", true)
    }

    pub fn starred_files_for_actor(&self, actor: &Actor) -> ApiResult<Vec<DriveFile>> {
        actor_file_page(
            self,
            actor,
            "f.starred = 1",
            "f.updated_at DESC, f.id DESC",
            true,
        )
    }

    pub fn shared_files_for_actor(&self, actor: &Actor) -> ApiResult<Vec<DriveFile>> {
        if actor.is_admin {
            return Ok(Vec::new());
        }
        actor_file_page(
            self,
            actor,
            "vw.access_role != 'owner'",
            "f.updated_at DESC, f.id DESC",
            false,
        )
    }

    pub fn list_activity(&self) -> rusqlite::Result<Vec<Activity>> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT id, kind, actor, target_id, created_at
             FROM activity ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(
            [i64::try_from(ACTIVITY_PAGE_LIMIT).unwrap_or(i64::MAX)],
            row_to_activity,
        )?;
        rows.collect()
    }

    pub fn list_activity_for_actor(&self, actor: &Actor) -> ApiResult<Vec<Activity>> {
        Ok(self
            .list_activity_for_actor_with_workspace_subjects(actor)?
            .0)
    }

    /// Select an activity page with the exact workspace and file subjects
    /// that made each non-admin row visible. The route rechecks those
    /// subjects immediately before JSON publication.
    pub(crate) fn list_activity_for_actor_with_workspace_subjects(
        &self,
        actor: &Actor,
    ) -> ApiResult<(Vec<Activity>, ActivityPublicationSubjects)> {
        if actor.is_admin {
            return Ok((
                self.list_activity()?,
                ActivityPublicationSubjects {
                    workspace_ids: Vec::new(),
                    file_ids: Vec::new(),
                },
            ));
        }
        let Some(scope) = actor_file_visibility_scope(actor) else {
            return Ok((
                Vec::new(),
                ActivityPublicationSubjects {
                    workspace_ids: Vec::new(),
                    file_ids: Vec::new(),
                },
            ));
        };
        let limit_parameter = scope.next_parameter;
        let item_visible = scope.visible_file_predicate("f");
        let effective_visibility = effectively_live_sql_predicate("f");
        let scoped_item_visible =
            format!("({item_visible} AND f.trashed = 0 AND {effective_visibility})");
        let mut parameters = scope.parameters;
        parameters.push(SqlValue::Integer(
            i64::try_from(ACTIVITY_PAGE_LIMIT).unwrap_or(i64::MAX),
        ));
        let sql = format!(
            "WITH RECURSIVE {}
             SELECT a.id, a.kind, a.actor, a.target_id, a.created_at,
                    CASE
                        WHEN EXISTS (
                            SELECT 1 FROM visible_workspaces subject_workspace
                            WHERE subject_workspace.id = f.workspace_id
                        ) THEN f.workspace_id
                        WHEN EXISTS (
                            SELECT 1 FROM visible_workspaces subject_workspace
                            WHERE subject_workspace.id = a.target_id
                        ) THEN a.target_id
                        ELSE NULL
                    END AS workspace_subject_id,
                    CASE
                        WHEN NOT EXISTS (
                            SELECT 1 FROM visible_workspaces workspace
                            WHERE workspace.id = f.workspace_id
                        ) AND {scoped_item_visible}
                        THEN f.id
                        ELSE NULL
                    END AS file_subject_id
             FROM activity a
             LEFT JOIN files f ON f.id = a.target_id
             WHERE EXISTS (
                     SELECT 1 FROM visible_workspaces vw WHERE vw.id = f.workspace_id
                   )
               OR EXISTS (
                     SELECT 1 FROM visible_workspaces vw WHERE vw.id = a.target_id
                   )
                OR {scoped_item_visible}
             ORDER BY a.created_at DESC, a.id DESC
             LIMIT ?{limit_parameter}",
            scope.cte_sql
        );
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(parameters.iter()), |row| {
            Ok((
                row_to_activity(row)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })?;
        let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let workspace_ids = rows
            .iter()
            .filter_map(|(_, workspace_id, _)| workspace_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let file_ids = rows
            .iter()
            .filter_map(|(_, _, file_id)| file_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok((
            rows.into_iter().map(|(activity, _, _)| activity).collect(),
            ActivityPublicationSubjects {
                workspace_ids,
                file_ids,
            },
        ))
    }
}

const SEARCH_SELECT: &str =
    "SELECT files.id, files.workspace_id, files.parent_id, files.name, files.kind,
            files.revision, files.trashed, files.starred, files.content_hash,
            files.created_at, files.updated_at, files.content_bytes, files.cover_hash,
            bm25(file_search_fts, 6.0, 3.0, 2.0, 1.0) AS rank,
            snippet(file_search_fts, 5, '<mark>', '</mark>', '…', 12) AS snippet,
            instr(snippet(file_search_fts, 2, char(31), char(30), '', 1), char(31)) > 0,
            instr(snippet(file_search_fts, 3, char(31), char(30), '', 1), char(31)) > 0,
            instr(snippet(file_search_fts, 4, char(31), char(30), '', 1), char(31)) > 0,
            instr(snippet(file_search_fts, 5, char(31), char(30), '', 1), char(31)) > 0
     FROM files
     JOIN file_search_fts ON file_search_fts.file_id = files.id";

fn row_to_search_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<SearchResult> {
    let file = row_to_file(row)?;
    let rank: f64 = row.get(13)?;
    let snippet: Option<String> = row.get(14)?;
    let mut matched_fields = Vec::new();
    for (index, field) in ["name", "labels", "metadata", "content"]
        .into_iter()
        .enumerate()
    {
        if row.get::<_, i64>(15 + index)? != 0 {
            matched_fields.push(field.to_string());
        }
    }
    Ok(SearchResult {
        file,
        rank: -rank,
        matched_fields,
        snippet,
    })
}

fn actor_file_page(
    storage: &Storage,
    actor: &Actor,
    predicate: &str,
    order_by: &str,
    include_item_grants: bool,
) -> ApiResult<Vec<DriveFile>> {
    let (cte_sql, mut parameters, limit_parameter, visible_file) = if include_item_grants {
        let Some(scope) = actor_file_visibility_scope(actor) else {
            return Ok(Vec::new());
        };
        let visible_file = scope.visible_file_predicate("f");
        (
            scope.cte_sql,
            scope.parameters,
            scope.next_parameter,
            visible_file,
        )
    } else {
        let Some(scope) = actor_workspace_scope(actor) else {
            return Ok(Vec::new());
        };
        (
            format!("visible_workspaces AS ({})", scope.sql),
            scope.parameters,
            scope.next_parameter,
            "vw.id IS NOT NULL".to_string(),
        )
    };
    parameters.push(SqlValue::Integer(
        i64::try_from(ALTERNATE_FILE_LIST_LIMIT).unwrap_or(i64::MAX),
    ));
    let effective_visibility = effectively_live_sql_predicate("f");
    let sql = format!(
        "WITH RECURSIVE {cte_sql}
         SELECT f.id, f.workspace_id, f.parent_id, f.name, f.kind, f.revision,
                f.trashed, f.starred, f.content_hash, f.created_at, f.updated_at,
                f.content_bytes, f.cover_hash
         FROM files f
         LEFT JOIN visible_workspaces vw ON vw.id = f.workspace_id
         WHERE f.trashed = 0 AND {predicate}
           AND {effective_visibility}
           AND {visible_file}
         ORDER BY {order_by}
         LIMIT ?{limit_parameter}"
    );
    let conn = storage.conn.lock().unwrap();
    let mut statement = conn.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(parameters.iter()), row_to_file)?;
    let mut files = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    attach_folder_sizes_if_bounded(&conn, &mut files)?;
    Ok(files)
}

fn attach_result_folder_sizes_if_bounded(
    conn: &rusqlite::Connection,
    results: &mut [SearchResult],
) -> ApiResult<()> {
    let mut files = results
        .iter()
        .map(|result| result.file.clone())
        .collect::<Vec<_>>();
    attach_folder_sizes_if_bounded(conn, &mut files)?;
    let sizes = files
        .into_iter()
        .map(|file| (file.id, file.folder_size_bytes))
        .collect::<HashMap<_, _>>();
    for result in results {
        result.file.folder_size_bytes = sizes.get(&result.file.id).copied().flatten();
    }
    Ok(())
}

fn attach_folder_sizes_if_bounded(
    conn: &rusqlite::Connection,
    files: &mut [DriveFile],
) -> ApiResult<()> {
    let mut workspace_ids = files
        .iter()
        .filter(|file| matches!(file.kind, crate::model::FileKind::Folder))
        .map(|file| file.workspace_id.as_str())
        .collect::<Vec<_>>();
    workspace_ids.sort_unstable();
    workspace_ids.dedup();
    if workspace_ids.is_empty() {
        return Ok(());
    }
    let placeholders = std::iter::repeat_n("?", workspace_ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let active_rows: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM files
             WHERE trashed = 0 AND workspace_id IN ({placeholders})"
        ),
        params_from_iter(workspace_ids.iter().copied()),
        |row| row.get(0),
    )?;
    if active_rows > MAX_COMPATIBILITY_FILE_LIST as i64 {
        return Ok(());
    }
    attach_folder_sizes_locked(conn, files)?;
    Ok(())
}

fn row_to_activity(row: &rusqlite::Row<'_>) -> rusqlite::Result<Activity> {
    Ok(Activity {
        id: row.get(0)?,
        kind: row.get(1)?,
        actor: row.get(2)?,
        target_id: row.get(3)?,
        created_at: row.get(4)?,
    })
}
