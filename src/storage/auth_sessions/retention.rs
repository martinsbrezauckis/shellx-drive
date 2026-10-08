use chrono::Utc;
use rusqlite::{params, Connection};

use crate::error::ApiResult;

pub(crate) const MAX_ACTIVE_AUTH_SESSIONS_PER_ACTOR: usize = 16;
const RETAIN_REVOKED_AUTH_SESSION_DAYS: i64 = 30;
const RETAIN_EXPIRED_AUTH_SESSION_DAYS: i64 = 7;
const MAX_RETAINED_AUTH_SESSION_HISTORY: usize = 10_000;

/// Keep auth-session storage bounded without ever deleting a still-valid
/// credential. This is called inside the same write transaction as issuance.
pub(super) fn prepare_auth_session_issuance_in_tx(conn: &Connection) -> ApiResult<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "DELETE FROM auth_sessions
         WHERE (revoked_at IS NOT NULL
                AND julianday(revoked_at) <= julianday(?1, ?2))
            OR (revoked_at IS NULL
                AND julianday(expires_at) <= julianday(?1, ?3))",
        params![
            &now,
            format!("-{RETAIN_REVOKED_AUTH_SESSION_DAYS} days"),
            format!("-{RETAIN_EXPIRED_AUTH_SESSION_DAYS} days"),
        ],
    )?;
    // Preserve the newest bounded audit history. Active sessions are excluded
    // deliberately: pruning must never silently invalidate a live login.
    conn.execute(
        "DELETE FROM auth_sessions
         WHERE id IN (
             SELECT id FROM auth_sessions
             WHERE revoked_at IS NOT NULL OR julianday(expires_at) <= julianday(?1)
             ORDER BY created_at DESC, id DESC
             LIMIT -1 OFFSET ?2
         )",
        params![
            &now,
            i64::try_from(MAX_RETAINED_AUTH_SESSION_HISTORY).unwrap_or(i64::MAX),
        ],
    )?;
    Ok(())
}

/// Retire only the oldest valid sessions for one actor. Every retired browser
/// session invalidates its Office derivative in this same transaction.
pub(super) fn enforce_active_session_limit_in_tx(
    conn: &Connection,
    actor_email: &str,
    new_session_id: &str,
) -> ApiResult<()> {
    let now = Utc::now().to_rfc3339();
    let mut statement = conn.prepare(
        "SELECT id FROM auth_sessions
         WHERE actor_email = ?1
           AND publication_pending = 0
           AND revoked_at IS NULL
           AND julianday(expires_at) > julianday(?2)
           AND id <> ?3
         ORDER BY created_at DESC, id DESC
         LIMIT -1 OFFSET ?4",
    )?;
    let retired_ids = statement
        .query_map(
            params![
                actor_email,
                &now,
                new_session_id,
                i64::try_from(MAX_ACTIVE_AUTH_SESSIONS_PER_ACTOR.saturating_sub(1))
                    .unwrap_or(i64::MAX),
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);

    for id in retired_ids {
        conn.execute(
            "UPDATE auth_sessions
             SET revoked_at = COALESCE(revoked_at, ?3)
             WHERE id = ?1 AND actor_email = ?2",
            params![&id, actor_email, &now],
        )?;
        conn.execute(
            "UPDATE office_edit_sessions
             SET used_at = COALESCE(used_at, ?3)
             WHERE source_credential_kind = 'user_session'
               AND source_credential_id = ?1 AND actor_email = ?2
               AND used_at IS NULL",
            params![&id, actor_email, &now],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
