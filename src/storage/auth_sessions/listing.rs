use chrono::Utc;
use rusqlite::{params, Row};

use crate::{
    error::ApiResult,
    model::{AccountSession, AuthSession},
};

use super::Storage;

pub(crate) struct AuthSessionPage {
    pub sessions: Vec<AccountSession>,
    pub total: usize,
    pub next_cursor: Option<(String, String)>,
}

impl Storage {
    pub fn list_auth_sessions(&self) -> ApiResult<Vec<AuthSession>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, actor_email, issuer, subject, expires_at, revoked_at, created_at
             FROM auth_sessions WHERE publication_pending = 0
             ORDER BY created_at DESC, id DESC",
        )?;
        let rows = stmt.query_map([], row_to_auth_session)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_auth_sessions_bounded(&self, limit: usize) -> ApiResult<Vec<AuthSession>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, actor_email, issuer, subject, expires_at, revoked_at, created_at
             FROM auth_sessions WHERE publication_pending = 0
             ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(
            [i64::try_from(limit).unwrap_or(i64::MAX)],
            row_to_auth_session,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// A complete, cursor-addressable view of valid sessions for the
    /// server-admin surface. Callers must present `total` and `next_cursor`
    /// rather than silently clipping older still-valid sessions.
    pub(crate) fn list_active_auth_sessions_page(
        &self,
        cursor: Option<(&str, &str)>,
        limit: usize,
    ) -> ApiResult<AuthSessionPage> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM auth_sessions
             WHERE publication_pending = 0
               AND revoked_at IS NULL AND julianday(expires_at) > julianday(?1)",
            params![&now],
            |row| row.get(0),
        )?;
        let fetch_limit = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
        let mut sessions = if let Some((cursor_created_at, cursor_id)) = cursor {
            let mut statement = conn.prepare(
                "SELECT id, actor_email, issuer, subject, expires_at, revoked_at, created_at,
                        client_ip, user_agent, last_seen_at
                 FROM auth_sessions
                 WHERE publication_pending = 0
                   AND revoked_at IS NULL
                   AND julianday(expires_at) > julianday(?1)
                   AND (created_at < ?2 OR (created_at = ?2 AND id < ?3))
                 ORDER BY created_at DESC, id DESC LIMIT ?4",
            )?;
            let rows = statement
                .query_map(
                    params![&now, cursor_created_at, cursor_id, fetch_limit],
                    row_to_account_session,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        } else {
            let mut statement = conn.prepare(
                "SELECT id, actor_email, issuer, subject, expires_at, revoked_at, created_at,
                        client_ip, user_agent, last_seen_at
                 FROM auth_sessions
                 WHERE publication_pending = 0
                   AND revoked_at IS NULL
                   AND julianday(expires_at) > julianday(?1)
                 ORDER BY created_at DESC, id DESC LIMIT ?2",
            )?;
            let rows = statement
                .query_map(params![&now, fetch_limit], row_to_account_session)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let next_cursor = (sessions.len() > limit)
            .then(|| sessions.pop())
            .flatten()
            .and_then(|_| sessions.last())
            .map(|session| {
                (
                    session.session.created_at.clone(),
                    session.session.id.clone(),
                )
            });
        Ok(AuthSessionPage {
            sessions,
            total: usize::try_from(total).unwrap_or(usize::MAX),
            next_cursor,
        })
    }

    /// Valid, non-revoked sessions owned by one signed-in account.
    pub fn list_active_auth_sessions_for_actor(
        &self,
        actor_email: &str,
    ) -> ApiResult<Vec<AccountSession>> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, actor_email, issuer, subject, expires_at, revoked_at, created_at,
                    client_ip, user_agent, last_seen_at
             FROM auth_sessions
             WHERE actor_email = ?1 AND publication_pending = 0
               AND revoked_at IS NULL
               AND julianday(expires_at) > julianday(?2)
             ORDER BY created_at DESC, id DESC",
        )?;
        let rows = stmt.query_map(params![actor_email, now], row_to_account_session)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

fn row_to_account_session(row: &Row<'_>) -> rusqlite::Result<AccountSession> {
    Ok(AccountSession {
        session: row_to_auth_session(row)?,
        client_ip: row.get(7)?,
        user_agent: row.get(8)?,
        last_seen_at: row.get(9)?,
    })
}

pub(super) fn row_to_auth_session(row: &Row<'_>) -> rusqlite::Result<AuthSession> {
    let revoked_at: Option<String> = row.get(5)?;
    Ok(AuthSession {
        id: row.get(0)?,
        actor_email: row.get(1)?,
        issuer: row.get(2)?,
        subject: row.get(3)?,
        expires_at: row.get(4)?,
        revoked: revoked_at.is_some(),
        revoked_at,
        created_at: row.get(6)?,
    })
}
