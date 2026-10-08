use rusqlite::{params, Connection};

use crate::error::{ApiError, ApiResult};

use super::{MAX_FILE_TREE_DEPTH, MAX_FILE_TREE_NODES};

/// Aggregate presentation buckets from one workspace-scoped traversal. The
/// sentinel is checked before recursion, so legacy rows cannot turn this
/// read-only endpoint into an unbounded per-row ancestry walk.
pub(crate) fn workspace_usage_buckets(
    conn: &Connection,
    workspace_id: &str,
) -> ApiResult<(i64, i64)> {
    let sentinel = MAX_FILE_TREE_NODES.saturating_add(1);
    let sql = format!(
        "WITH RECURSIVE workspace_files AS MATERIALIZED (
             SELECT id, parent_id, trashed, content_bytes, cover_bytes
             FROM files INDEXED BY idx_files_workspace_parent
             WHERE workspace_id = ?1
             LIMIT {sentinel}
         ),
         node_count(count) AS (
             SELECT COUNT(*) FROM workspace_files
         ),
         effective_tree(id, depth, live) AS (
             SELECT root.id, 0, CASE WHEN root.trashed = 0 THEN 1 ELSE 0 END
             FROM workspace_files root
             CROSS JOIN node_count
             WHERE node_count.count <= {MAX_FILE_TREE_NODES} AND root.parent_id IS NULL
             UNION ALL
             SELECT child.id, tree.depth + 1,
                    CASE WHEN tree.live = 1 AND child.trashed = 0 THEN 1 ELSE 0 END
             FROM effective_tree tree
             JOIN files child INDEXED BY idx_files_workspace_parent
               ON child.workspace_id = ?1 AND child.parent_id = tree.id
             WHERE tree.depth < {MAX_FILE_TREE_DEPTH}
         )
         SELECT node_count.count,
                COALESCE(SUM(CASE WHEN effective_tree.live = 1
                                  THEN workspace_files.content_bytes
                                     + CASE WHEN workspace_files.cover_bytes > 0
                                            THEN workspace_files.cover_bytes ELSE 0 END
                                  ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN effective_tree.live = 1 THEN 0
                                  ELSE workspace_files.content_bytes
                                     + CASE WHEN workspace_files.cover_bytes > 0
                                            THEN workspace_files.cover_bytes ELSE 0 END END), 0)
         FROM node_count
         LEFT JOIN workspace_files ON 1 = 1
         LEFT JOIN effective_tree ON effective_tree.id = workspace_files.id
         GROUP BY node_count.count"
    );
    let (node_count, current_file_bytes, trashed_file_bytes) =
        conn.query_row(&sql, params![workspace_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get(1)?, row.get(2)?))
        })?;
    if node_count > MAX_FILE_TREE_NODES as i64 {
        return Err(ApiError::PayloadTooLarge(format!(
            "workspace file tree exceeds the {MAX_FILE_TREE_NODES}-item usage limit"
        )));
    }
    Ok((current_file_bytes, trashed_file_bytes))
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use rusqlite::params;

    use super::*;
    use crate::storage::Storage;

    fn insert_file(
        conn: &rusqlite::Transaction<'_>,
        id: &str,
        workspace_id: &str,
        parent_id: Option<&str>,
        kind: &str,
        content_bytes: i64,
    ) {
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO files (
                 id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                 content_hash, content_bytes, created_at, updated_at, cover_hash, cover_bytes
             ) VALUES (?1, ?2, ?3, ?1, ?4, 1, 0, 0, NULL, ?5, ?6, ?6, NULL, 0)",
            params![id, workspace_id, parent_id, kind, content_bytes, now],
        )
        .unwrap();
    }

    fn storage_with_workspace() -> (tempfile::TempDir, Storage, String) {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::open(root.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let (workspace, _, _) = storage
            .create_workspace("usage", "owner@example.test")
            .unwrap();
        (root, storage, workspace.id)
    }

    #[test]
    fn usage_accepts_a_legal_deep_tree_and_rejects_the_node_sentinel() {
        let (_root, storage, workspace_id) = storage_with_workspace();
        let empty_usage = storage.workspace_usage(&workspace_id).unwrap();
        assert_eq!(empty_usage.current_file_bytes, 0);
        assert_eq!(empty_usage.trashed_file_bytes, 0);
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        let mut parent_id = None;
        for depth in 0..MAX_FILE_TREE_DEPTH {
            let id = format!("depth-{depth}");
            insert_file(&tx, &id, &workspace_id, parent_id.as_deref(), "folder", 0);
            parent_id = Some(id);
        }
        for index in 0..MAX_FILE_TREE_NODES - MAX_FILE_TREE_DEPTH {
            insert_file(
                &tx,
                &format!("leaf-{index}"),
                &workspace_id,
                parent_id.as_deref(),
                "file",
                1,
            );
        }
        tx.commit().unwrap();
        drop(conn);

        let usage = storage.workspace_usage(&workspace_id).unwrap();
        assert_eq!(
            usage.current_file_bytes,
            (MAX_FILE_TREE_NODES - MAX_FILE_TREE_DEPTH) as i64
        );
        assert_eq!(usage.trashed_file_bytes, 0);

        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO files (
                 id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                 content_hash, content_bytes, created_at, updated_at, cover_hash, cover_bytes
             ) VALUES ('over-limit', ?1, NULL, 'over-limit', 'file', 1, 0, 0, NULL, 1,
                       ?2, ?2, NULL, 0)",
            params![workspace_id, Utc::now().to_rfc3339()],
        )
        .unwrap();
        drop(conn);
        assert!(matches!(
            storage.workspace_usage(&workspace_id),
            Err(ApiError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn usage_projects_malformed_parent_chains_to_trash() {
        let (_root, storage, workspace_id) = storage_with_workspace();
        let (foreign, _, _) = storage
            .create_workspace("foreign", "owner@example.test")
            .unwrap();
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        insert_file(&tx, "live", &workspace_id, None, "file", 1);
        insert_file(&tx, "missing", &workspace_id, Some("absent"), "file", 2);
        insert_file(&tx, "cycle-a", &workspace_id, Some("cycle-b"), "file", 3);
        insert_file(&tx, "cycle-b", &workspace_id, Some("cycle-a"), "folder", 0);
        insert_file(&tx, "foreign-root", &foreign.id, None, "folder", 0);
        insert_file(
            &tx,
            "cross-workspace",
            &workspace_id,
            Some("foreign-root"),
            "file",
            4,
        );
        let mut parent_id = None;
        for depth in 0..=MAX_FILE_TREE_DEPTH {
            let id = format!("too-deep-{depth}");
            insert_file(&tx, &id, &workspace_id, parent_id.as_deref(), "folder", 0);
            parent_id = Some(id);
        }
        insert_file(
            &tx,
            "too-deep-file",
            &workspace_id,
            parent_id.as_deref(),
            "file",
            5,
        );
        tx.commit().unwrap();
        drop(conn);

        let usage = storage.workspace_usage(&workspace_id).unwrap();
        assert_eq!(usage.current_file_bytes, 1);
        assert_eq!(usage.trashed_file_bytes, 14);
    }
}
