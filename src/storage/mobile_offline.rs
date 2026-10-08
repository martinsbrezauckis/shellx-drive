use std::collections::{HashMap, HashSet};

use chrono::Utc;
use rusqlite::{params, params_from_iter, types::Value as SqlValue, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{DriveFile, MobileOfflineFile, Receipt},
};

use super::{
    bounded_files::{
        effectively_live_sql_predicate, file_is_effectively_trashed_locked,
        retain_effectively_live_file_ids_locked,
    },
    human_item_grants::{
        access::ensure_item_authorized_in_tx, actor_visibility::actor_file_visibility_scope,
    },
    insert_receipt_rows, new_receipt, row_to_mobile_offline_file, Storage, MAX_FILE_TREE_NODES,
};

impl Storage {
    pub fn list_mobile_offline_files(&self) -> ApiResult<Vec<MobileOfflineFile>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT actor_email, workspace_id, file_id, marked_at
             FROM mobile_offline_files ORDER BY marked_at DESC, file_id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(
            [i64::try_from(MAX_FILE_TREE_NODES).unwrap_or(i64::MAX)],
            row_to_mobile_offline_file,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_mobile_offline_files_for_actor(
        &self,
        actor: &Actor,
    ) -> ApiResult<Vec<MobileOfflineFile>> {
        let Some(scope) = actor_file_visibility_scope(actor) else {
            return Ok(Vec::new());
        };
        let limit_parameter = scope.next_parameter;
        let visible_file = scope.visible_file_predicate("f");
        let mut parameters = scope.parameters;
        parameters.push(SqlValue::Integer(
            i64::try_from(MAX_FILE_TREE_NODES).unwrap_or(i64::MAX),
        ));
        let effective_visibility = effectively_live_sql_predicate("f");
        let sql = format!(
            "WITH RECURSIVE {}
             SELECT mof.actor_email, mof.workspace_id, mof.file_id, mof.marked_at
             FROM mobile_offline_files mof
             JOIN files f ON f.id = mof.file_id AND f.workspace_id = mof.workspace_id
             WHERE mof.actor_email = ?1
               AND f.trashed = 0
               AND {effective_visibility}
               AND {visible_file}
             ORDER BY mof.marked_at DESC, mof.file_id DESC
             LIMIT ?{limit_parameter}",
            scope.cte_sql
        );
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params_from_iter(parameters.iter()),
            row_to_mobile_offline_file,
        )?;
        let mut files = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut file_ids = files
            .iter()
            .map(|file| file.file_id.clone())
            .collect::<HashSet<_>>();
        retain_effectively_live_file_ids_locked(&conn, &mut file_ids)?;
        files.retain(|file| file_ids.contains(&file.file_id));
        Ok(files)
    }

    /// A sync manifest already contains the complete effectively-live tree.
    /// Intersect actor marks with that bounded snapshot using the actor and
    /// workspace index, avoiding another parent walk for every marked file.
    pub(crate) fn mobile_offline_file_ids_for_manifest(
        &self,
        actor_email: &str,
        workspace_id: &str,
        manifest_files: &[DriveFile],
    ) -> ApiResult<HashSet<String>> {
        let live_ids = manifest_files
            .iter()
            .map(|file| file.id.as_str())
            .collect::<HashSet<_>>();
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT file_id FROM mobile_offline_files INDEXED BY idx_mobile_offline_actor_workspace
             WHERE actor_email = ?1 AND workspace_id = ?2
             LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                actor_email,
                workspace_id,
                i64::try_from(MAX_FILE_TREE_NODES.saturating_add(1)).unwrap_or(i64::MAX)
            ],
            |row| row.get::<_, String>(0),
        )?;
        let ids = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if ids.len() > MAX_FILE_TREE_NODES {
            return Err(ApiError::PayloadTooLarge(format!(
                "mobile offline selection exceeds the {MAX_FILE_TREE_NODES}-item limit"
            )));
        }
        Ok(ids
            .into_iter()
            .filter(|id| live_ids.contains(id.as_str()))
            .collect())
    }

    /// Count all of an actor's effectively-live offline marks in one indexed
    /// read. The caller maps only its currently authorized workspaces into the
    /// response; the durable per-actor mark ceiling bounds this query.
    pub(crate) fn mobile_offline_counts_for_actor(
        &self,
        actor_email: &str,
    ) -> ApiResult<HashMap<String, i64>> {
        let effective_visibility = effectively_live_sql_predicate("f");
        let sql = format!(
            "SELECT mof.workspace_id, COUNT(*)
             FROM mobile_offline_files mof INDEXED BY idx_mobile_offline_actor_workspace
             JOIN files f ON f.id = mof.file_id AND f.workspace_id = mof.workspace_id
             WHERE mof.actor_email = ?1 AND f.trashed = 0
               AND {effective_visibility}
             GROUP BY mof.workspace_id"
        );
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([actor_email], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<HashMap<_, _>>>()?)
    }

    pub fn is_mobile_offline_file(&self, actor_email: &str, file_id: &str) -> ApiResult<bool> {
        let marked = {
            let conn = self.conn.lock().unwrap();
            let count: i64 = conn.query_row(
                "SELECT COUNT(*)
                 FROM mobile_offline_files mof
                 JOIN files f ON f.id = mof.file_id AND f.workspace_id = mof.workspace_id
                 WHERE mof.actor_email = ?1 AND mof.file_id = ?2 AND f.trashed = 0",
                params![actor_email, file_id],
                |row| row.get(0),
            )?;
            count > 0
        };
        Ok(marked && !self.file_is_effectively_trashed(file_id)?)
    }

    pub fn set_mobile_offline_file(
        &self,
        actor: &Actor,
        source_credential: &DriveCredential,
        workspace_id: &str,
        file_id: &str,
        offline: bool,
    ) -> ApiResult<Receipt> {
        let now = Utc::now().to_rfc3339();
        let receipt_kind = if offline {
            "mobile.offline.mark"
        } else {
            "mobile.offline.unmark"
        };
        let receipt = new_receipt(receipt_kind, &actor.email, Some(file_id));
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let access = ensure_item_authorized_in_tx(
            &tx,
            file_id,
            actor,
            source_credential,
            WorkspacePermission::Read,
        )?;
        if access.workspace_id != workspace_id {
            return Err(ApiError::NotFound);
        }
        if offline {
            let active: i64 = tx.query_row(
                "SELECT EXISTS(
                       SELECT 1 FROM files
                       WHERE id = ?1 AND workspace_id = ?2 AND trashed = 0
                     )",
                params![file_id, workspace_id],
                |row| row.get(0),
            )?;
            if active == 0 {
                return Err(ApiError::NotFound);
            }
            if file_is_effectively_trashed_locked(&tx, file_id)? {
                return Err(ApiError::NotFound);
            }
            let existing: i64 = tx.query_row(
                "SELECT EXISTS(
                       SELECT 1 FROM mobile_offline_files
                       WHERE actor_email = ?1 AND file_id = ?2
                     )",
                params![&actor.email, file_id],
                |row| row.get(0),
            )?;
            if existing == 0 {
                let marks: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM mobile_offline_files WHERE actor_email = ?1",
                    params![&actor.email],
                    |row| row.get(0),
                )?;
                if marks >= MAX_FILE_TREE_NODES as i64 {
                    return Err(ApiError::PayloadTooLarge(format!(
                        "mobile offline selection accepts at most {MAX_FILE_TREE_NODES} files per actor"
                    )));
                }
            }
            tx.execute(
                "INSERT INTO mobile_offline_files (actor_email, workspace_id, file_id, marked_at)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(actor_email, file_id) DO UPDATE SET
                        workspace_id = excluded.workspace_id,
                        marked_at = excluded.marked_at",
                params![&actor.email, workspace_id, file_id, &now],
            )?;
        } else {
            tx.execute(
                "DELETE FROM mobile_offline_files WHERE actor_email = ?1 AND file_id = ?2",
                params![&actor.email, file_id],
            )?;
        }
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;

    #[test]
    fn grouped_offline_counts_handle_wide_selection_and_hide_trash() {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let first = storage
            .create_workspace("First", "owner@example.test")
            .unwrap()
            .0;
        let second = storage
            .create_workspace("Second", "owner@example.test")
            .unwrap()
            .0;
        let now = Utc::now().to_rfc3339();
        {
            let mut conn = storage.conn.lock().unwrap();
            let tx = conn.transaction().unwrap();
            for index in 0..1_000 {
                let workspace_id = if index % 2 == 0 {
                    &first.id
                } else {
                    &second.id
                };
                let file_id = format!("offline-{index}");
                tx.execute(
                    "INSERT INTO files (id, workspace_id, name, kind, revision, trashed,
                                        starred, content_bytes, created_at, updated_at)
                     VALUES (?1, ?2, ?3, 'file', 1, ?4, 0, 0, ?5, ?5)",
                    params![file_id, workspace_id, file_id, i64::from(index == 0), now],
                )
                .unwrap();
                tx.execute(
                    "INSERT INTO mobile_offline_files (actor_email, workspace_id, file_id, marked_at)
                     VALUES ('owner@example.test', ?1, ?2, ?3)",
                    params![workspace_id, file_id, now],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        let counts = storage
            .mobile_offline_counts_for_actor("owner@example.test")
            .unwrap();
        assert_eq!(counts.get(&first.id), Some(&499));
        assert_eq!(counts.get(&second.id), Some(&500));
        let manifest = storage
            .list_sync_manifest_files(&first.id, MAX_FILE_TREE_NODES)
            .unwrap();
        assert_eq!(
            storage
                .mobile_offline_file_ids_for_manifest("owner@example.test", &first.id, &manifest)
                .unwrap()
                .len(),
            499
        );
        assert!(storage
            .mobile_offline_counts_for_actor("other@example.test")
            .unwrap()
            .is_empty());
    }
}
