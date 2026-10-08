use chrono::{Duration, Utc};
use rusqlite::{params, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{token_hash, Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    storage::Storage,
};

use super::{
    ensure_lock_owner, find_lock_by_token_locked, load_tree_locked, load_workspace_locks_locked,
    lock_covers_resource, purge_expired_locked, scope_contains, validate_lock_input, WebDavLock,
    WebDavLockDepth,
};
use crate::storage::authorization;

impl Storage {
    pub fn create_webdav_lock(
        &self,
        workspace_id: &str,
        resource_id: Option<&str>,
        resource_path: &str,
        owner_email: &str,
        depth: WebDavLockDepth,
        timeout_seconds: i64,
    ) -> ApiResult<WebDavLock> {
        self.create_webdav_lock_inner(
            workspace_id,
            resource_id,
            resource_path,
            owner_email,
            depth,
            timeout_seconds,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_webdav_lock_authorized(
        &self,
        workspace_id: &str,
        resource_id: Option<&str>,
        resource_path: &str,
        depth: WebDavLockDepth,
        timeout_seconds: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<WebDavLock> {
        self.create_webdav_lock_inner(
            workspace_id,
            resource_id,
            resource_path,
            &actor.email,
            depth,
            timeout_seconds,
            Some((actor, source_credential)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_webdav_lock_inner(
        &self,
        workspace_id: &str,
        resource_id: Option<&str>,
        resource_path: &str,
        owner_email: &str,
        depth: WebDavLockDepth,
        timeout_seconds: i64,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<WebDavLock> {
        validate_lock_input(resource_path, owner_email, timeout_seconds)?;
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let expires_at = (now + Duration::seconds(timeout_seconds)).to_rfc3339();
        let token = format!("opaquelocktoken:{}", Uuid::new_v4());
        let lock = WebDavLock {
            id: Uuid::now_v7().to_string(),
            workspace_id: workspace_id.to_string(),
            resource_id: resource_id.map(str::to_string),
            resource_path: resource_path.to_string(),
            owner_email: owner_email.trim().to_ascii_lowercase(),
            scope: "exclusive".to_string(),
            depth,
            token: token.clone(),
            timeout_seconds,
            expires_at,
            created_at: now_text.clone(),
            updated_at: now_text,
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((actor, source_credential)) = authorization_context {
            authorization::ensure_whole_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
        }
        purge_expired_locked(&tx)?;
        let tree = load_tree_locked(&tx, workspace_id)?;
        let existing = load_workspace_locks_locked(&tx, workspace_id)?;
        if existing.iter().any(|candidate| {
            lock_covers_resource(candidate, resource_id, &tree)
                || (depth == WebDavLockDepth::Infinity
                    && scope_contains(resource_id, candidate.resource_id.as_deref(), &tree))
        }) {
            return Err(ApiError::Locked);
        }
        tx.execute(
            "INSERT INTO webdav_locks (
                id, workspace_id, resource_id, resource_path, owner_email, scope,
                depth, token, token_hash, timeout_seconds, expires_at, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'exclusive', ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
            params![
                &lock.id,
                &lock.workspace_id,
                &lock.resource_id,
                &lock.resource_path,
                &lock.owner_email,
                lock.depth.as_str(),
                &lock.token,
                token_hash(&token),
                lock.timeout_seconds,
                &lock.expires_at,
                &lock.created_at,
            ],
        )?;
        tx.commit()?;
        Ok(lock)
    }

    pub fn refresh_webdav_lock(
        &self,
        workspace_id: &str,
        resource_id: Option<&str>,
        token: &str,
        actor_email: &str,
        actor_is_admin: bool,
        timeout_seconds: i64,
    ) -> ApiResult<WebDavLock> {
        self.refresh_webdav_lock_inner(
            workspace_id,
            resource_id,
            token,
            actor_email,
            actor_is_admin,
            timeout_seconds,
            None,
        )
    }

    pub(crate) fn refresh_webdav_lock_authorized(
        &self,
        workspace_id: &str,
        resource_id: Option<&str>,
        token: &str,
        timeout_seconds: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<WebDavLock> {
        self.refresh_webdav_lock_inner(
            workspace_id,
            resource_id,
            token,
            &actor.email,
            actor.is_admin,
            timeout_seconds,
            Some((actor, source_credential)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn refresh_webdav_lock_inner(
        &self,
        workspace_id: &str,
        resource_id: Option<&str>,
        token: &str,
        actor_email: &str,
        actor_is_admin: bool,
        timeout_seconds: i64,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<WebDavLock> {
        validate_lock_input("", actor_email, timeout_seconds)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((actor, source_credential)) = authorization_context {
            authorization::ensure_whole_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
        }
        purge_expired_locked(&tx)?;
        let lock = find_lock_by_token_locked(&tx, token)?.ok_or(ApiError::PreconditionFailed)?;
        if lock.workspace_id != workspace_id {
            return Err(ApiError::PreconditionFailed);
        }
        let tree = load_tree_locked(&tx, workspace_id)?;
        if !lock_covers_resource(&lock, resource_id, &tree) {
            return Err(ApiError::PreconditionFailed);
        }
        ensure_lock_owner(&lock, actor_email, actor_is_admin)?;
        let now = Utc::now();
        let updated_at = now.to_rfc3339();
        let expires_at = (now + Duration::seconds(timeout_seconds)).to_rfc3339();
        tx.execute(
            "UPDATE webdav_locks
             SET timeout_seconds = ?1, expires_at = ?2, updated_at = ?3
             WHERE id = ?4",
            params![timeout_seconds, &expires_at, &updated_at, &lock.id],
        )?;
        tx.commit()?;
        Ok(WebDavLock {
            timeout_seconds,
            expires_at,
            updated_at,
            ..lock
        })
    }

    pub fn unlock_webdav_lock(
        &self,
        workspace_id: &str,
        resource_id: Option<&str>,
        token: &str,
        actor_email: &str,
        actor_is_admin: bool,
    ) -> ApiResult<()> {
        self.unlock_webdav_lock_inner(
            workspace_id,
            resource_id,
            token,
            actor_email,
            actor_is_admin,
            None,
        )
    }

    pub(crate) fn unlock_webdav_lock_authorized(
        &self,
        workspace_id: &str,
        resource_id: Option<&str>,
        token: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        self.unlock_webdav_lock_inner(
            workspace_id,
            resource_id,
            token,
            &actor.email,
            actor.is_admin,
            Some((actor, source_credential)),
        )
    }

    fn unlock_webdav_lock_inner(
        &self,
        workspace_id: &str,
        resource_id: Option<&str>,
        token: &str,
        actor_email: &str,
        actor_is_admin: bool,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((actor, source_credential)) = authorization_context {
            authorization::ensure_whole_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
        }
        purge_expired_locked(&tx)?;
        let lock = find_lock_by_token_locked(&tx, token)?.ok_or(ApiError::Conflict)?;
        if lock.workspace_id != workspace_id {
            return Err(ApiError::Conflict);
        }
        let tree = load_tree_locked(&tx, workspace_id)?;
        if !lock_covers_resource(&lock, resource_id, &tree) {
            return Err(ApiError::Conflict);
        }
        ensure_lock_owner(&lock, actor_email, actor_is_admin)?;
        tx.execute("DELETE FROM webdav_locks WHERE id = ?1", params![lock.id])?;
        tx.commit()?;
        Ok(())
    }
}
