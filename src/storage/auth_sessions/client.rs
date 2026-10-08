use chrono::Utc;
use rusqlite::params;

use crate::{error::ApiResult, model::AuthSession};

use super::{insert_auth_session_in_tx, Storage};

impl Storage {
    #[allow(clippy::too_many_arguments)]
    pub fn record_auth_session_with_client(
        &self,
        id: &str,
        actor_email: &str,
        issuer: &str,
        subject: &str,
        token_hash: &str,
        expires_at: &str,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> ApiResult<AuthSession> {
        let session = AuthSession {
            id: id.to_string(),
            actor_email: actor_email.to_string(),
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            expires_at: expires_at.to_string(),
            revoked_at: None,
            created_at: Utc::now().to_rfc3339(),
            revoked: false,
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        insert_auth_session_in_tx(&tx, &session, token_hash, false)?;
        set_auth_session_client_in_tx(&tx, id, client_ip, user_agent)?;
        tx.commit()?;
        Ok(session)
    }

    /// Refresh a browser session's observed client metadata at most every five
    /// minutes. This keeps “last seen” useful without turning every request
    /// into a database write.
    pub fn touch_auth_session_client(
        &self,
        id: &str,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> ApiResult<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE auth_sessions
             SET client_ip = COALESCE(?2, client_ip),
                 user_agent = COALESCE(?3, user_agent),
                 last_seen_at = ?4
             WHERE id = ?1
               AND (last_seen_at IS NULL OR julianday(last_seen_at) <= julianday(?4, '-5 minutes'))",
            params![id, client_ip, user_agent, now],
        )?;
        Ok(())
    }
}

pub(super) fn set_auth_session_client_in_tx(
    conn: &rusqlite::Connection,
    id: &str,
    client_ip: Option<&str>,
    user_agent: Option<&str>,
) -> ApiResult<()> {
    conn.execute(
        "UPDATE auth_sessions
         SET client_ip = ?2, user_agent = ?3, last_seen_at = created_at
         WHERE id = ?1",
        params![id, client_ip, user_agent],
    )?;
    Ok(())
}
