mod mutations;

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use rusqlite::{params, OptionalExtension, Row};
use serde::Serialize;

use super::Storage;
use crate::{
    auth::token_hash,
    error::{ApiError, ApiResult},
};

const MAX_DEBUG_LOCKS: i64 = 200;
pub const MAX_WEBDAV_LOCK_TIMEOUT_SECONDS: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebDavLockDepth {
    Zero,
    Infinity,
}

impl WebDavLockDepth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zero => "0",
            Self::Infinity => "infinity",
        }
    }

    fn from_db(value: &str) -> Self {
        match value {
            "infinity" => Self::Infinity,
            _ => Self::Zero,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebDavLock {
    pub id: String,
    pub workspace_id: String,
    pub resource_id: Option<String>,
    pub resource_path: String,
    pub owner_email: String,
    pub scope: String,
    pub depth: WebDavLockDepth,
    pub token: String,
    pub timeout_seconds: i64,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub enum WebDavMutationTarget {
    Resource(Option<String>),
    Membership(Option<String>),
    Subtree(Option<String>),
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugWebDavLock {
    pub lock_ref: String,
    pub workspace_id: String,
    pub resource_ref: String,
    pub resource_present: bool,
    pub path_depth: usize,
    pub owner_ref: String,
    pub scope: String,
    pub depth: String,
    pub timeout_seconds: i64,
    pub expires_at: String,
    pub created_at: String,
}

impl Storage {
    pub fn ensure_webdav_mutation_allowed(
        &self,
        workspace_id: &str,
        targets: &[WebDavMutationTarget],
        submitted_tokens: &HashSet<String>,
        actor_email: &str,
        actor_is_admin: bool,
    ) -> ApiResult<()> {
        let submitted_hashes = submitted_tokens
            .iter()
            .map(|token| token_hash(token))
            .collect::<HashSet<_>>();
        let conn = self.conn.lock().unwrap();
        purge_expired_locked(&conn)?;
        let tree = load_tree_locked(&conn, workspace_id)?;
        for lock in load_workspace_locks_locked(&conn, workspace_id)? {
            if lock_applies_to_targets(&lock, targets, &tree) {
                let token_matches = submitted_hashes.contains(&token_hash(&lock.token));
                let actor_owns_lock = actor_is_admin || lock.owner_email == actor_email;
                if !token_matches || !actor_owns_lock {
                    return Err(ApiError::Locked);
                }
            }
        }
        Ok(())
    }

    pub fn webdav_locks_covering_resource(
        &self,
        workspace_id: &str,
        resource_id: Option<&str>,
    ) -> ApiResult<Vec<WebDavLock>> {
        let conn = self.conn.lock().unwrap();
        purge_expired_locked(&conn)?;
        let tree = load_tree_locked(&conn, workspace_id)?;
        Ok(load_workspace_locks_locked(&conn, workspace_id)?
            .into_iter()
            .filter(|lock| lock_covers_resource(lock, resource_id, &tree))
            .collect())
    }

    pub fn list_active_webdav_locks(&self, workspace_id: &str) -> ApiResult<Vec<WebDavLock>> {
        let conn = self.conn.lock().unwrap();
        purge_expired_locked(&conn)?;
        Ok(load_workspace_locks_locked(&conn, workspace_id)?)
    }

    pub fn delete_webdav_locks_in_subtree(
        &self,
        workspace_id: &str,
        root_id: Option<&str>,
    ) -> ApiResult<()> {
        let conn = self.conn.lock().unwrap();
        let tree = load_tree_locked(&conn, workspace_id)?;
        let ids = load_workspace_locks_locked(&conn, workspace_id)?
            .into_iter()
            .filter(|lock| scope_contains(root_id, lock.resource_id.as_deref(), &tree))
            .map(|lock| lock.id)
            .collect::<Vec<_>>();
        for id in ids {
            conn.execute("DELETE FROM webdav_locks WHERE id = ?1", params![id])?;
        }
        Ok(())
    }

    pub fn debug_webdav_locks(&self) -> ApiResult<(i64, Vec<DebugWebDavLock>)> {
        let conn = self.conn.lock().unwrap();
        purge_expired_locked(&conn)?;
        let total = conn.query_row("SELECT COUNT(*) FROM webdav_locks", [], |row| row.get(0))?;
        let mut statement = conn.prepare(
            "SELECT id, workspace_id, resource_id, resource_path, owner_email, scope,
                    depth, token, timeout_seconds, expires_at, created_at, updated_at
             FROM webdav_locks ORDER BY expires_at ASC, id ASC LIMIT ?1",
        )?;
        let locks = statement
            .query_map(params![MAX_DEBUG_LOCKS], row_to_lock)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let present_ids = load_present_resource_ids_locked(&conn)?;
        let debug = locks
            .into_iter()
            .map(|lock| DebugWebDavLock {
                lock_ref: format!("webdav-lock-{}", &token_hash(&lock.id)[..12]),
                workspace_id: lock.workspace_id,
                resource_ref: lock
                    .resource_id
                    .as_ref()
                    .map(|id| format!("file-{}", &token_hash(id)[..12]))
                    .unwrap_or_else(|| "workspace-root".to_string()),
                resource_present: lock
                    .resource_id
                    .as_ref()
                    .map(|id| present_ids.contains(id))
                    .unwrap_or(true),
                path_depth: lock
                    .resource_path
                    .split('/')
                    .filter(|part| !part.is_empty())
                    .count(),
                owner_ref: format!("actor-{}", &token_hash(&lock.owner_email)[..12]),
                scope: lock.scope,
                depth: lock.depth.as_str().to_string(),
                timeout_seconds: lock.timeout_seconds,
                expires_at: lock.expires_at,
                created_at: lock.created_at,
            })
            .collect();
        Ok((total, debug))
    }
}

fn validate_lock_input(path: &str, owner_email: &str, timeout_seconds: i64) -> ApiResult<()> {
    if path.len() > 4096 || owner_email.trim().is_empty() || owner_email.len() > 320 {
        return Err(ApiError::Validation(
            "invalid WebDAV lock resource or owner".to_string(),
        ));
    }
    if !(1..=MAX_WEBDAV_LOCK_TIMEOUT_SECONDS).contains(&timeout_seconds) {
        return Err(ApiError::Validation(
            "WebDAV lock timeout is outside the supported range".to_string(),
        ));
    }
    Ok(())
}

fn purge_expired_locked(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM webdav_locks WHERE expires_at <= ?1",
        params![Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

fn load_workspace_locks_locked(
    conn: &rusqlite::Connection,
    workspace_id: &str,
) -> rusqlite::Result<Vec<WebDavLock>> {
    let mut statement = conn.prepare(
        "SELECT id, workspace_id, resource_id, resource_path, owner_email, scope,
                depth, token, timeout_seconds, expires_at, created_at, updated_at
         FROM webdav_locks WHERE workspace_id = ?1 ORDER BY created_at ASC, id ASC",
    )?;
    let locks = statement
        .query_map(params![workspace_id], row_to_lock)?
        .collect();
    locks
}

fn find_lock_by_token_locked(
    conn: &rusqlite::Connection,
    token: &str,
) -> rusqlite::Result<Option<WebDavLock>> {
    conn.query_row(
        "SELECT id, workspace_id, resource_id, resource_path, owner_email, scope,
                depth, token, timeout_seconds, expires_at, created_at, updated_at
         FROM webdav_locks WHERE token_hash = ?1",
        params![token_hash(token)],
        row_to_lock,
    )
    .optional()
}

fn row_to_lock(row: &Row<'_>) -> rusqlite::Result<WebDavLock> {
    let depth: String = row.get(6)?;
    Ok(WebDavLock {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        resource_id: row.get(2)?,
        resource_path: row.get(3)?,
        owner_email: row.get(4)?,
        scope: row.get(5)?,
        depth: WebDavLockDepth::from_db(&depth),
        token: row.get(7)?,
        timeout_seconds: row.get(8)?,
        expires_at: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn load_tree_locked(
    conn: &rusqlite::Connection,
    workspace_id: &str,
) -> rusqlite::Result<HashMap<String, Option<String>>> {
    let mut statement = conn.prepare("SELECT id, parent_id FROM files WHERE workspace_id = ?1")?;
    let rows = statement.query_map(params![workspace_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
    rows.collect()
}

fn load_present_resource_ids_locked(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<HashSet<String>> {
    let mut statement = conn.prepare("SELECT id FROM files WHERE trashed = 0")?;
    let rows = statement.query_map([], |row| row.get(0))?;
    rows.collect()
}

fn lock_covers_resource(
    lock: &WebDavLock,
    resource_id: Option<&str>,
    tree: &HashMap<String, Option<String>>,
) -> bool {
    lock.resource_id.as_deref() == resource_id
        || (lock.depth == WebDavLockDepth::Infinity
            && scope_contains(lock.resource_id.as_deref(), resource_id, tree))
}

fn scope_contains(
    root_id: Option<&str>,
    candidate_id: Option<&str>,
    tree: &HashMap<String, Option<String>>,
) -> bool {
    match (root_id, candidate_id) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(root), Some(candidate)) => {
            let mut current = Some(candidate);
            let mut visited = HashSet::new();
            while let Some(id) = current {
                if id == root {
                    return true;
                }
                if !visited.insert(id.to_string()) {
                    return false;
                }
                current = tree.get(id).and_then(|parent| parent.as_deref());
            }
            false
        }
    }
}

fn lock_applies_to_targets(
    lock: &WebDavLock,
    targets: &[WebDavMutationTarget],
    tree: &HashMap<String, Option<String>>,
) -> bool {
    targets.iter().any(|target| match target {
        WebDavMutationTarget::Resource(id) | WebDavMutationTarget::Membership(id) => {
            lock_covers_resource(lock, id.as_deref(), tree)
        }
        WebDavMutationTarget::Subtree(root) => {
            lock_covers_resource(lock, root.as_deref(), tree)
                || scope_contains(root.as_deref(), lock.resource_id.as_deref(), tree)
        }
    })
}

fn ensure_lock_owner(lock: &WebDavLock, actor_email: &str, actor_is_admin: bool) -> ApiResult<()> {
    if actor_is_admin || lock.owner_email.eq_ignore_ascii_case(actor_email.trim()) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_lock_is_visible_after_storage_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("drive.db");
        let first = Storage::open(db.clone()).unwrap();
        first.migrate().unwrap();
        let (workspace, _, _) = first
            .create_workspace("Persistent DAV", "owner@example.test")
            .unwrap();
        let created = first
            .create_webdav_lock(
                &workspace.id,
                None,
                "",
                "owner@example.test",
                WebDavLockDepth::Infinity,
                3600,
            )
            .unwrap();
        drop(first);

        let reopened = Storage::open(db).unwrap();
        reopened.migrate().unwrap();
        let covering = reopened
            .webdav_locks_covering_resource(&workspace.id, None)
            .unwrap();
        assert_eq!(covering.len(), 1);
        assert_eq!(covering[0].token, created.token);
    }
}
