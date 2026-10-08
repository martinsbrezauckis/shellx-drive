use chrono::{Duration, Utc};
use rand::RngCore;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{token_hash, Actor, AuthMode, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::DebugOfficeSession,
};

use super::{
    human_item_grants::access::ensure_item_authorized_in_tx, normalize_storage_email,
    row_to_office_edit_session, Storage,
};

const MAX_ACTIVE_OFFICE_SESSIONS_GLOBAL: i64 = 1_000;
const MAX_ACTIVE_OFFICE_SESSIONS_PER_ACTOR: i64 = 8;
const MAX_ACTIVE_OFFICE_SESSIONS_PER_FILE: i64 = 8;

impl Storage {
    pub fn create_office_edit_session(
        &self,
        file_id: &str,
        actor_email: &str,
        source_credential: &DriveCredential,
        base_revision: i64,
        provider_name: &str,
        ttl_seconds: i64,
    ) -> ApiResult<(DebugOfficeSession, String)> {
        let actor_email = normalize_storage_email(actor_email)?;
        let mut token_bytes = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let raw_token = hex::encode(token_bytes);
        let token_hash = token_hash(&raw_token);
        let (source_credential_kind, source_credential_id, source_credential_generation) =
            match source_credential {
                DriveCredential::Operator => (
                    "operator",
                    None,
                    Some(self.operator_credential_generation.as_ref()),
                ),
                DriveCredential::UserSession(id) => (
                    "user_session",
                    Some(id.as_str()),
                    Some(self.operator_credential_generation.as_ref()),
                ),
                DriveCredential::AppToken(id) => ("app_token", Some(id.as_str()), None),
                DriveCredential::DelegatedAgentToken(id) => {
                    ("delegated_agent", Some(id.as_str()), None)
                }
            };
        let now = Utc::now();
        let session = DebugOfficeSession {
            id: Uuid::now_v7().to_string(),
            file_id: file_id.to_string(),
            actor_email,
            base_revision,
            provider_name: provider_name.to_string(),
            expires_at: (now + Duration::seconds(ttl_seconds.max(60))).to_rfc3339(),
            used_at: None,
            created_at: now.to_rfc3339(),
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.query_row(
            "SELECT 1 FROM files WHERE id = ?1",
            params![file_id],
            |_| Ok(()),
        )
        .optional()?
        .ok_or(ApiError::NotFound)?;
        let credential_is_active = match source_credential {
            DriveCredential::Operator => true,
            DriveCredential::UserSession(session_id) => {
                tx.query_row(
                    "SELECT EXISTS(
                    SELECT 1 FROM auth_sessions
                    WHERE id = ?1 AND actor_email = ?2 AND revoked_at IS NULL
                      AND publication_pending = 0
                      AND julianday(expires_at) > julianday(?3)
                 )",
                    params![session_id, &session.actor_email, &session.created_at],
                    |row| row.get::<_, i64>(0),
                )? != 0
            }
            DriveCredential::AppToken(token_id) => {
                tx.query_row(
                    "SELECT EXISTS(
                    SELECT 1 FROM app_tokens
                    WHERE id = ?1 AND actor_email = ?2 AND revoked_at IS NULL
                      AND publication_pending = 0
                      AND julianday(expires_at) > julianday(?3)
                 )",
                    params![token_id, &session.actor_email, &session.created_at],
                    |row| row.get::<_, i64>(0),
                )? != 0
            }
            DriveCredential::DelegatedAgentToken(token_id) => {
                let owner = tx
                    .query_row(
                        "SELECT p.created_by, p.creator_authority_kind
                         FROM agent_tokens t
                         JOIN agent_principals p ON p.id = t.principal_id
                         WHERE t.id = ?1 AND t.delegation_kind = 'delegated'
                           AND t.revoked_at IS NULL AND p.disabled_at IS NULL
                           AND t.publication_pending = 0 AND p.publication_pending = 0
                           AND julianday(t.expires_at) > julianday(?2)",
                        params![token_id, &session.created_at],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?;
                owner.is_some_and(|(owner_email, authority_kind)| {
                    owner_email == session.actor_email
                        && if authority_kind == "operator" {
                            owner_email == crate::auth::ADMIN_ACTOR
                        } else {
                            tx.query_row(
                                "SELECT 1 FROM auth_accounts
                                 WHERE email = ?1 AND disabled_at IS NULL",
                                params![owner_email],
                                |_| Ok(()),
                            )
                            .optional()
                            .ok()
                            .flatten()
                            .is_some()
                        }
                })
            }
        };
        if !credential_is_active {
            return Err(ApiError::Unauthenticated);
        }
        tx.execute(
            "DELETE FROM office_edit_sessions
             WHERE used_at IS NOT NULL OR julianday(expires_at) <= julianday(?1)",
            params![&session.created_at],
        )?;
        let active_global: i64 =
            tx.query_row("SELECT COUNT(*) FROM office_edit_sessions", [], |row| {
                row.get(0)
            })?;
        let active_actor: i64 = tx.query_row(
            "SELECT COUNT(*) FROM office_edit_sessions WHERE actor_email = ?1",
            params![&session.actor_email],
            |row| row.get(0),
        )?;
        let active_file: i64 = tx.query_row(
            "SELECT COUNT(*) FROM office_edit_sessions WHERE file_id = ?1",
            params![&session.file_id],
            |row| row.get(0),
        )?;
        if active_global >= MAX_ACTIVE_OFFICE_SESSIONS_GLOBAL
            || active_actor >= MAX_ACTIVE_OFFICE_SESSIONS_PER_ACTOR
            || active_file >= MAX_ACTIVE_OFFICE_SESSIONS_PER_FILE
        {
            return Err(ApiError::TooManyRequests);
        }
        tx.execute(
            "INSERT INTO office_edit_sessions (
                id, token_hash, file_id, actor_email, base_revision, provider_name,
                source_credential_kind, source_credential_id,
                source_credential_generation, expires_at, used_at, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11)",
            params![
                &session.id,
                &token_hash,
                &session.file_id,
                &session.actor_email,
                session.base_revision,
                &session.provider_name,
                source_credential_kind,
                source_credential_id,
                source_credential_generation,
                &session.expires_at,
                &session.created_at,
            ],
        )?;
        tx.commit()?;
        Ok((session, raw_token))
    }

    pub fn get_office_edit_session_by_token(
        &self,
        raw_token: &str,
    ) -> ApiResult<Option<DebugOfficeSession>> {
        let token_hash = token_hash(raw_token);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let row: Option<(DebugOfficeSession, String, Option<String>, Option<String>)> = tx
            .query_row(
                "SELECT id, file_id, actor_email, base_revision, provider_name,
                    expires_at, used_at, created_at, source_credential_kind,
                    source_credential_id, source_credential_generation
             FROM office_edit_sessions o
             WHERE o.token_hash = ?1",
                params![token_hash],
                |row| {
                    Ok((
                        row_to_office_edit_session(row)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .optional()?;
        let Some((session, source_kind, source_id, source_generation)) = row else {
            return Ok(None);
        };
        let source_credential = match (
            source_kind.as_str(),
            source_id,
            source_generation.as_deref(),
        ) {
            ("operator", None, Some(generation))
                if generation == self.operator_credential_generation.as_ref() =>
            {
                DriveCredential::Operator
            }
            ("user_session", Some(id), Some(generation))
                if generation == self.operator_credential_generation.as_ref() =>
            {
                DriveCredential::UserSession(id)
            }
            ("app_token", Some(id), None) => DriveCredential::AppToken(id),
            ("delegated_agent", Some(id), None) => DriveCredential::DelegatedAgentToken(id),
            _ => return Ok(None),
        };
        let actor = Actor {
            email: session.actor_email.clone(),
            is_admin: false,
            auth_mode: if matches!(source_credential, DriveCredential::DelegatedAgentToken(_)) {
                AuthMode::DelegatedAgent
            } else {
                AuthMode::OfficeSession
            },
            allowed_workspace_ids: None,
        };
        match ensure_item_authorized_in_tx(
            &tx,
            &session.file_id,
            &actor,
            &source_credential,
            WorkspacePermission::Write,
        ) {
            Ok(_) => Ok(Some(session)),
            Err(ApiError::Unauthenticated | ApiError::Forbidden | ApiError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Atomically consumes an Office edit session only while the capability's
    /// originating credential and the actor's current workspace Write role are
    /// still valid. The caller must retain the returned credential and use an
    /// authorized content-write transaction for the final publication.
    pub(crate) fn claim_office_edit_session_authorized(
        &self,
        raw_token: &str,
    ) -> ApiResult<(DebugOfficeSession, Actor, DriveCredential)> {
        let now = Utc::now().to_rfc3339();
        let token_hash = token_hash(raw_token);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (mut session, source_kind, source_id, source_generation): (
            DebugOfficeSession,
            String,
            Option<String>,
            Option<String>,
        ) = tx
            .query_row(
                "SELECT id, file_id, actor_email, base_revision, provider_name,
                        expires_at, used_at, created_at, source_credential_kind,
                        source_credential_id, source_credential_generation
                 FROM office_edit_sessions
                 WHERE token_hash = ?1 AND used_at IS NULL
                   AND julianday(expires_at) > julianday(?2)",
                params![&token_hash, &now],
                |row| {
                    Ok((
                        DebugOfficeSession {
                            id: row.get(0)?,
                            file_id: row.get(1)?,
                            actor_email: row.get(2)?,
                            base_revision: row.get(3)?,
                            provider_name: row.get(4)?,
                            expires_at: row.get(5)?,
                            used_at: row.get(6)?,
                            created_at: row.get(7)?,
                        },
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        let current_generation = self.operator_credential_generation.as_ref();
        let source_credential = match (
            source_kind.as_str(),
            source_id,
            source_generation.as_deref(),
        ) {
            ("operator", None, Some(generation)) if generation == current_generation => {
                DriveCredential::Operator
            }
            ("user_session", Some(id), Some(generation)) if generation == current_generation => {
                DriveCredential::UserSession(id)
            }
            ("app_token", Some(id), None) => DriveCredential::AppToken(id),
            ("delegated_agent", Some(id), None) => DriveCredential::DelegatedAgentToken(id),
            _ => return Err(ApiError::Unauthenticated),
        };
        let actor = Actor {
            email: session.actor_email.clone(),
            // Office handoffs have always required membership, including for
            // an operator-created session acting as a named workspace user.
            is_admin: false,
            auth_mode: if matches!(source_credential, DriveCredential::DelegatedAgentToken(_)) {
                AuthMode::DelegatedAgent
            } else {
                AuthMode::OfficeSession
            },
            allowed_workspace_ids: None,
        };
        let _workspace_id: String = tx
            .query_row(
                "SELECT workspace_id FROM files WHERE id = ?1",
                params![&session.file_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        ensure_item_authorized_in_tx(
            &tx,
            &session.file_id,
            &actor,
            &source_credential,
            WorkspacePermission::Write,
        )?;
        if tx.execute(
            "UPDATE office_edit_sessions SET used_at = ?1
             WHERE id = ?2 AND token_hash = ?3 AND used_at IS NULL
               AND julianday(expires_at) > julianday(?1)",
            params![&now, &session.id, &token_hash],
        )? != 1
        {
            return Err(ApiError::Forbidden);
        }
        session.used_at = Some(now);
        tx.commit()?;
        Ok((session, actor, source_credential))
    }

    pub fn revoke_office_edit_sessions_for_actor(&self, actor_email: &str) -> ApiResult<usize> {
        let actor_email = normalize_storage_email(actor_email)?;
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute(
            "UPDATE office_edit_sessions
             SET used_at = COALESCE(used_at, ?2)
             WHERE actor_email = ?1 AND used_at IS NULL",
            params![actor_email, now],
        )?)
    }

    pub(crate) fn discard_unclaimed_office_edit_session(&self, id: &str) -> ApiResult<()> {
        let conn = self.conn.lock().unwrap();
        if conn.execute(
            "DELETE FROM office_edit_sessions WHERE id = ?1 AND used_at IS NULL",
            params![id],
        )? != 1
        {
            return Err(ApiError::NotFound);
        }
        Ok(())
    }

    pub fn list_office_edit_sessions(&self) -> ApiResult<Vec<DebugOfficeSession>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, file_id, actor_email, base_revision, provider_name,
                    expires_at, used_at, created_at
             FROM office_edit_sessions ORDER BY created_at DESC, id DESC LIMIT 1000",
        )?;
        let rows = stmt.query_map([], row_to_office_edit_session)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_debug_office_sessions_redacted(&self) -> ApiResult<Vec<DebugOfficeSession>> {
        self.list_office_edit_sessions()
    }
}
