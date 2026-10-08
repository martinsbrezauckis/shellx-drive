use chrono::Utc;
use rusqlite::{params, OptionalExtension};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission, WorkspaceRole},
    download_subjects::{CurrentFileSubject, FileContentSubject},
    error::{ApiError, ApiResult},
};

use super::{
    download_subjects, human_item_grants::access::ensure_item_authorized_in_tx, Storage,
    MAX_FILE_TREE_DEPTH,
};

mod metadata_publication;
mod publication_liveness;
mod share_archive;

const LOCAL_PASSWORD_ISSUER: &str = "local-password";

/// Revalidate both the human credential and current workspace write authority
/// inside the transaction which mints a durable agent capability.
pub(super) fn ensure_agent_creator_authorized(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    ensure_workspace_authorized(
        tx,
        workspace_id,
        actor,
        source_credential,
        WorkspacePermission::Write,
    )
}

/// Revalidate the originating session or application token against current
/// durable state. Local administrators are also rebound to the account's
/// current admin bit, preventing a demoted session from committing privileged
/// work already in flight.
pub(crate) fn ensure_source_credential_active(
    tx: &rusqlite::Transaction<'_>,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    match source_credential {
        DriveCredential::Operator => Ok(()),
        DriveCredential::AppToken(token_id) => {
            let now = Utc::now().to_rfc3339();
            let active = tx
                .query_row(
                    "SELECT 1 FROM app_tokens t
                     WHERE t.id = ?1 AND t.actor_email = ?2
                       AND t.revoked_at IS NULL
                       AND t.publication_pending = 0
                       AND julianday(t.expires_at) > julianday(?3)
                       AND NOT EXISTS (
                           SELECT 1 FROM auth_accounts a
                           WHERE a.email = t.actor_email AND a.disabled_at IS NOT NULL
                       )",
                    params![token_id, &actor.email, &now],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if active {
                Ok(())
            } else {
                Err(ApiError::Unauthenticated)
            }
        }
        DriveCredential::UserSession(session_id) => {
            let now = Utc::now().to_rfc3339();
            let issuer = tx
                .query_row(
                    "SELECT issuer FROM auth_sessions
                     WHERE id = ?1 AND actor_email = ?2 AND revoked_at IS NULL
                       AND publication_pending = 0
                       AND julianday(expires_at) > julianday(?3)",
                    params![session_id, &actor.email, &now],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or(ApiError::Unauthenticated)?;
            if issuer == LOCAL_PASSWORD_ISSUER {
                let account_admin = tx
                    .query_row(
                        "SELECT is_admin FROM auth_accounts
                         WHERE email = ?1 AND disabled_at IS NULL",
                        params![&actor.email],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?
                    .ok_or(ApiError::Unauthenticated)?
                    != 0;
                if actor.is_admin && !account_admin {
                    return Err(ApiError::Forbidden);
                }
            }
            Ok(())
        }
        DriveCredential::DelegatedAgentToken(token_id) => {
            let now = Utc::now().to_rfc3339();
            let owner = tx
                .query_row(
                    "SELECT p.id, p.created_by, p.creator_authority_kind, p.delegation_parent_kind
                     FROM agent_tokens t
                     JOIN agent_principals p ON p.id = t.principal_id
                     WHERE t.id = ?1 AND t.delegation_kind = 'delegated'
                       AND t.revoked_at IS NULL AND p.disabled_at IS NULL
                       AND t.publication_pending = 0 AND p.publication_pending = 0
                       AND julianday(t.expires_at) > julianday(?2)",
                    params![token_id, &now],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                        ))
                    },
                )
                .optional()?
                .ok_or(ApiError::Unauthenticated)?;
            let (principal_id, owner_email, owner_authority_kind, parent_kind) = owner;
            if actor.email != owner_email
                || actor.auth_mode != crate::auth::AuthMode::DelegatedAgent
            {
                return Err(ApiError::Unauthenticated);
            }
            match parent_kind.as_str() {
                "external_sso" => {
                    if !crate::storage::agent_access::delegated_sso_parent_is_active(
                        tx,
                        &principal_id,
                        &owner_email,
                    )? {
                        return Err(ApiError::Unauthenticated);
                    }
                    if actor.is_admin {
                        return Err(ApiError::Forbidden);
                    }
                    return Ok(());
                }
                "local" => {
                    if crate::storage::agent_access::delegated_sso_parent_is_active(
                        tx,
                        &principal_id,
                        &owner_email,
                    )? {
                        return Err(ApiError::Unauthenticated);
                    }
                }
                _ => return Err(ApiError::Unauthenticated),
            }
            let current_is_admin = if owner_authority_kind == "operator" {
                if owner_email != crate::auth::ADMIN_ACTOR {
                    return Err(ApiError::Unauthenticated);
                }
                true
            } else {
                tx.query_row(
                    "SELECT is_admin FROM auth_accounts
                     WHERE email = ?1 AND disabled_at IS NULL",
                    params![&owner_email],
                    |row| Ok(row.get::<_, i64>(0)? != 0),
                )
                .optional()?
                .ok_or(ApiError::Unauthenticated)?
            };
            // A role transition between request authentication and terminal
            // publication wins over the delegated request. The next request
            // may authenticate with the newly reduced role if still allowed.
            if actor.is_admin && !current_is_admin {
                return Err(ApiError::Forbidden);
            }
            Ok(())
        }
    }
}

pub(crate) fn ensure_admin_authorized(
    tx: &rusqlite::Transaction<'_>,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    ensure_source_credential_active(tx, actor, source_credential)?;
    if actor.is_admin && !matches!(source_credential, DriveCredential::AppToken(_)) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

pub(crate) fn ensure_local_account_self_authorized(
    tx: &rusqlite::Transaction<'_>,
    email: &str,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    ensure_source_credential_active(tx, actor, source_credential)?;
    if actor.email == email
        && matches!(
            source_credential,
            DriveCredential::UserSession(_) | DriveCredential::DelegatedAgentToken(_)
        )
    {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Revalidate both the source credential and current workspace role in the
/// transaction that publishes a tenant mutation or derived capability.
pub(crate) fn ensure_workspace_authorized(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    actor: &Actor,
    source_credential: &DriveCredential,
    permission: WorkspacePermission,
) -> ApiResult<()> {
    ensure_source_credential_active(tx, actor, source_credential)?;
    if actor.is_admin {
        return Ok(());
    }
    if let DriveCredential::AppToken(token_id) = source_credential {
        let scope_json = tx
            .query_row(
                "SELECT workspace_ids_json FROM app_tokens WHERE id = ?1",
                params![token_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(ApiError::Unauthenticated)?;
        let scope: Vec<String> =
            serde_json::from_str(&scope_json).map_err(|_| ApiError::Unauthenticated)?;
        if !scope.iter().any(|allowed| allowed == workspace_id) {
            return Err(ApiError::Forbidden);
        }
    }
    let now = Utc::now().to_rfc3339();
    let role = tx
        .query_row(
            "SELECT role FROM (
                 SELECT wm.role AS role
                 FROM workspace_members wm
                 JOIN users u ON u.id = wm.user_id
                 WHERE wm.workspace_id = ?1 AND u.email = ?2
                   AND (wm.expires_at IS NULL OR wm.expires_at > ?3)
                 UNION ALL
                 SELECT wgg.role AS role
                 FROM workspace_group_grants wgg
                 JOIN group_members gm ON gm.group_id = wgg.group_id
                 JOIN users u ON u.id = gm.user_id
                 WHERE wgg.workspace_id = ?1 AND u.email = ?2
             )
             ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'editor' THEN 1 ELSE 2 END
             LIMIT 1",
            params![workspace_id, &actor.email, &now],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let role = role.and_then(|role| WorkspaceRole::parse(&role));
    if role.is_some_and(|role| role.allows(permission)) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// WebDAV remains a whole-workspace protocol. This intentionally does not
/// consult item grants: a scoped grantee must be rejected before path
/// resolution or directory listing can disclose sibling names.
pub(crate) fn ensure_whole_workspace_authorized(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    actor: &Actor,
    source_credential: &DriveCredential,
    permission: WorkspacePermission,
) -> ApiResult<()> {
    ensure_workspace_authorized(tx, workspace_id, actor, source_credential, permission)
}

impl Storage {
    /// WebDAV remains a whole-workspace protocol.  It deliberately does not
    /// consult item grants: a DAV URL names and can enumerate an entire
    /// workspace, so an item recipient must be denied before path resolution.
    pub(crate) fn ensure_whole_workspace_permission(
        &self,
        workspace_id: &str,
        actor: &Actor,
        permission: WorkspacePermission,
    ) -> ApiResult<()> {
        self.ensure_workspace_permission(workspace_id, actor, permission)
    }

    /// Revalidate an already-admitted human source credential immediately
    /// before publishing account-owned management metadata.
    pub(crate) fn ensure_source_credential_publication_authorized(
        &self,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        ensure_source_credential_active(&tx, actor, source_credential)?;
        tx.commit()?;
        Ok(())
    }

    /// Permit publication of the small acknowledgement produced by a guarded
    /// self-disable or self-demotion. The account change and the proof are
    /// bound to one security-version transition; a later password change,
    /// disable, token/session revocation, or account mutation wins.
    pub(crate) fn ensure_self_removal_completion_authorized(
        &self,
        actor: &Actor,
        source_credential: &DriveCredential,
        expected_security_version: i64,
        source_credential_was_revoked: bool,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let (security_version, disabled_at, updated_at) = tx
            .query_row(
                "SELECT security_version, disabled_at, updated_at
                 FROM auth_accounts WHERE email = ?1",
                params![&actor.email],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(ApiError::Unauthenticated)?;
        if security_version != expected_security_version {
            return Err(ApiError::Unauthenticated);
        }
        if source_credential_was_revoked {
            if disabled_at.is_none()
                || !source_credential_revoked_at(&tx, actor, source_credential, &updated_at)?
            {
                return Err(ApiError::Unauthenticated);
            }
        } else {
            if disabled_at.is_some() {
                return Err(ApiError::Unauthenticated);
            }
            let reduced_actor = Actor {
                email: actor.email.clone(),
                is_admin: false,
                auth_mode: actor.auth_mode,
                allowed_workspace_ids: actor.allowed_workspace_ids.clone(),
            };
            ensure_source_credential_active(&tx, &reduced_actor, source_credential)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Revalidate account-wide administrator authority immediately before a
    /// buffered admin response is published.
    pub(crate) fn ensure_admin_publication_authorized(
        &self,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        ensure_admin_authorized(&tx, actor, source_credential)?;
        tx.commit()?;
        Ok(())
    }

    /// Revalidate one workspace permission at the terminal response boundary.
    /// Buffered management responses use this after selecting sensitive
    /// capability metadata so a concurrent revoke or role downgrade wins
    /// before JSON publication.
    pub(crate) fn ensure_workspace_publication_authorized(
        &self,
        workspace_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
        permission: WorkspacePermission,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        ensure_workspace_authorized(&tx, workspace_id, actor, source_credential, permission)?;
        tx.commit()?;
        Ok(())
    }

    /// Revalidate the source credential and every workspace whose metadata was
    /// selected for a buffered response immediately before publication.
    ///
    /// This is deliberately separate from single-workspace/file publication:
    /// account-wide sync responses can select metadata from several workspaces,
    /// and every selected subject must remain readable at the terminal point.
    pub(crate) fn ensure_workspace_metadata_publication_authorized(
        &self,
        workspace_ids: &[String],
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        ensure_source_credential_active(&tx, actor, source_credential)?;
        metadata_publication::ensure_workspace_metadata_subjects_authorized(
            &tx,
            workspace_ids,
            actor,
            source_credential,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn ensure_share_file_ticket_authorized(
        &self,
        share_root_id: &str,
        file_id: &str,
        content_subject: &CurrentFileSubject,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let (workspace_id, root_trashed): (String, i64) = tx
            .query_row(
                "SELECT workspace_id, trashed FROM files WHERE id = ?1",
                params![share_root_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        if root_trashed != 0 {
            return Err(ApiError::NotFound);
        }
        let mut current = Some(file_id.to_string());
        let mut visited = std::collections::HashSet::new();
        let mut reached_root = false;
        for _ in 0..=MAX_FILE_TREE_DEPTH {
            let Some(id) = current.take() else {
                break;
            };
            if !visited.insert(id.clone()) {
                return Err(ApiError::NotFound);
            }
            let (row_workspace, parent_id, trashed): (String, Option<String>, i64) = tx
                .query_row(
                    "SELECT workspace_id, parent_id, trashed FROM files WHERE id = ?1",
                    params![&id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if row_workspace != workspace_id || trashed != 0 {
                return Err(ApiError::NotFound);
            }
            if id == share_root_id {
                reached_root = true;
                break;
            }
            current = parent_id;
        }
        if !reached_root {
            return Err(ApiError::NotFound);
        }
        download_subjects::ensure_current_file_subjects(
            &tx,
            &[file_id.to_string()],
            std::slice::from_ref(content_subject),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Revalidate a short-lived download capability against its originating
    /// credential, current workspace role, and effective trash ancestry just
    /// before response-body publication.
    pub(crate) fn ensure_download_ticket_authorized(
        &self,
        workspace_id: &str,
        file_ids: &[String],
        content_subjects: &[FileContentSubject],
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        ensure_download_ticket_authorized_in_tx(
            &tx,
            workspace_id,
            file_ids,
            content_subjects,
            actor,
            source_credential,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn ensure_thumbnail_publication_authorized(
        &self,
        workspace_id: &str,
        file_id: &str,
        revision: i64,
        thumbnail_hash: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
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
        publication_liveness::ensure_files_effectively_live(
            &tx,
            workspace_id,
            &[file_id.to_string()],
        )?;
        let attached = tx
            .query_row(
                "SELECT 1
                 FROM file_previews previews
                 JOIN files ON files.id = previews.file_id
                 WHERE previews.file_id = ?1 AND previews.workspace_id = ?2
                   AND previews.revision = ?3 AND previews.revision = files.revision
                   AND previews.thumbnail_hash = ?4",
                params![file_id, workspace_id, revision, thumbnail_hash],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !attached {
            return Err(ApiError::NotFound);
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn ensure_cover_publication_authorized(
        &self,
        workspace_id: &str,
        file_id: &str,
        cover_hash: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
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
        publication_liveness::ensure_files_effectively_live(
            &tx,
            workspace_id,
            &[file_id.to_string()],
        )?;
        let attached = tx
            .query_row(
                "SELECT 1 FROM files
                 WHERE id = ?1 AND workspace_id = ?2 AND kind = 'folder'
                   AND cover_hash = ?3",
                params![file_id, workspace_id, cover_hash],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !attached {
            return Err(ApiError::NotFound);
        }
        tx.commit()?;
        Ok(())
    }
}

pub(super) fn ensure_download_ticket_authorized_in_tx(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    file_ids: &[String],
    content_subjects: &[FileContentSubject],
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    if file_ids.is_empty() {
        ensure_workspace_authorized(
            tx,
            workspace_id,
            actor,
            source_credential,
            WorkspacePermission::Read,
        )?;
    } else {
        for file_id in file_ids {
            let access = ensure_item_authorized_in_tx(
                tx,
                file_id,
                actor,
                source_credential,
                WorkspacePermission::Read,
            )?;
            if access.workspace_id != workspace_id {
                return Err(ApiError::NotFound);
            }
        }
    }
    publication_liveness::ensure_files_effectively_live(tx, workspace_id, file_ids)?;
    download_subjects::ensure_file_content_subjects(tx, file_ids, content_subjects)?;
    Ok(())
}

fn source_credential_revoked_at(
    tx: &rusqlite::Transaction<'_>,
    actor: &Actor,
    source_credential: &DriveCredential,
    expected_revoked_at: &str,
) -> ApiResult<bool> {
    let revoked_at = match source_credential {
        DriveCredential::UserSession(session_id) => tx
            .query_row(
                "SELECT revoked_at FROM auth_sessions
                 WHERE id = ?1 AND actor_email = ?2",
                params![session_id, &actor.email],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?,
        DriveCredential::DelegatedAgentToken(token_id) => tx
            .query_row(
                "SELECT t.revoked_at FROM agent_tokens t
                 JOIN agent_principals p ON p.id = t.principal_id
                 WHERE t.id = ?1 AND t.delegation_kind = 'delegated'
                   AND p.created_by = ?2",
                params![token_id, &actor.email],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?,
        DriveCredential::Operator | DriveCredential::AppToken(_) => return Ok(false),
    };
    Ok(revoked_at.flatten().as_deref() == Some(expected_revoked_at))
}
