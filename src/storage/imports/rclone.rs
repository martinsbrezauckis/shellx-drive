use rusqlite::Connection;

use crate::{
    error::{ApiError, ApiResult},
    model::DriveFile,
    storage::bounded_files::effectively_live_sql_predicate,
};

pub(super) fn query_active_files(
    conn: &Connection,
    workspace_id: &str,
    max_entries: usize,
) -> ApiResult<Vec<DriveFile>> {
    let query_limit = max_entries
        .checked_add(1)
        .and_then(|limit| i64::try_from(limit).ok())
        .ok_or_else(|| {
            ApiError::Validation("rclone v1 export entry limit is invalid".to_string())
        })?;
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
    let rows = statement.query_map(
        rusqlite::params![workspace_id, query_limit],
        crate::storage::row_to_file,
    )?;
    let files = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    if files.len() > max_entries {
        return Err(ApiError::Validation(format!(
            "rclone v1 legacy export exceeds its {max_entries}-active-entry maximum; use native streamed file APIs for larger exports"
        )));
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use rusqlite::{params, Connection};

    use super::query_active_files;
    use crate::storage::imports::RCLONE_V1_MAX_ACTIVE_EXPORT_ENTRIES;

    fn test_connection() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE files (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                parent_id TEXT,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                revision INTEGER NOT NULL,
                trashed INTEGER NOT NULL,
                starred INTEGER NOT NULL,
                content_hash TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                content_bytes INTEGER NOT NULL,
                cover_hash TEXT
            );",
        )
        .unwrap();
        conn
    }

    fn insert_file(conn: &Connection, id: &str) {
        conn.execute(
            "INSERT INTO files (
                id, workspace_id, parent_id, name, kind, revision, trashed,
                starred, content_hash, created_at, updated_at, content_bytes,
                cover_hash
             ) VALUES (?1, 'workspace', NULL, ?1, 'file', 1, 0, 0, NULL,
                '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0, NULL)",
            params![id],
        )
        .unwrap();
    }

    #[test]
    fn query_fetches_one_extra_active_row_and_refuses_excess() {
        assert_eq!(RCLONE_V1_MAX_ACTIVE_EXPORT_ENTRIES, 10_000);
        let conn = test_connection();
        insert_file(&conn, "one");
        insert_file(&conn, "two");

        let error = query_active_files(&conn, "workspace", 1).unwrap_err();
        assert!(error
            .to_string()
            .contains("rclone v1 legacy export exceeds its 1-active-entry maximum"));
    }

    #[test]
    fn query_hides_an_active_legacy_child_of_trashed_parent() {
        let conn = test_connection();
        conn.execute(
            "INSERT INTO files (
                id, workspace_id, parent_id, name, kind, revision, trashed,
                starred, content_hash, created_at, updated_at, content_bytes,
                cover_hash
             ) VALUES ('trashed-parent', 'workspace', NULL, 'parent', 'folder', 1, 1, 0, NULL,
                       '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0, NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO files (
                id, workspace_id, parent_id, name, kind, revision, trashed,
                starred, content_hash, created_at, updated_at, content_bytes,
                cover_hash
             ) VALUES ('legacy-child', 'workspace', 'trashed-parent', 'child', 'file', 1, 0,
                       0, NULL, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0, NULL)",
            [],
        )
        .unwrap();

        assert!(query_active_files(&conn, "workspace", 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn hidden_legacy_rows_do_not_consume_the_export_limit() {
        let conn = test_connection();
        conn.execute(
            "INSERT INTO files (
                id, workspace_id, parent_id, name, kind, revision, trashed,
                starred, content_hash, created_at, updated_at, content_bytes,
                cover_hash
             ) VALUES ('trashed-parent', 'workspace', NULL, 'parent', 'folder', 1, 1, 0, NULL,
                       '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0, NULL)",
            [],
        )
        .unwrap();
        for (id, updated_at) in [
            ("hidden-first", "9999-01-01T00:00:02Z"),
            ("hidden-second", "9999-01-01T00:00:01Z"),
        ] {
            conn.execute(
                "INSERT INTO files (
                    id, workspace_id, parent_id, name, kind, revision, trashed,
                    starred, content_hash, created_at, updated_at, content_bytes,
                    cover_hash
                 ) VALUES (?1, 'workspace', 'trashed-parent', ?1, 'file', 1, 0, 0, NULL,
                           '2026-01-01T00:00:00Z', ?2, 0, NULL)",
                params![id, updated_at],
            )
            .unwrap();
        }
        insert_file(&conn, "live");

        let files = query_active_files(&conn, "workspace", 1).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].id, "live");
    }
}
