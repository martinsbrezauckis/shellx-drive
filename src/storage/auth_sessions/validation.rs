use chrono::DateTime;
use rusqlite::{params, OptionalExtension};

use crate::{
    auth::constant_time_str_eq,
    error::{ApiError, ApiResult},
};

use super::Storage;

impl Storage {
    pub fn ensure_auth_session_active(
        &self,
        id: &str,
        token_hash: &str,
        now_epoch: i64,
    ) -> ApiResult<()> {
        let conn = self.conn.lock().unwrap();
        let session = conn
            .query_row(
                "SELECT token_hash, expires_at, revoked_at
                 FROM auth_sessions WHERE id = ?1 AND publication_pending = 0",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((stored_hash, expires_at, revoked_at)) = session else {
            return Err(ApiError::Unauthenticated);
        };
        if !constant_time_str_eq(&stored_hash, token_hash) || revoked_at.is_some() {
            return Err(ApiError::Unauthenticated);
        }
        let expires_at = DateTime::parse_from_rfc3339(&expires_at)
            .map_err(|_| ApiError::Unauthenticated)?
            .timestamp();
        if expires_at <= now_epoch {
            return Err(ApiError::Unauthenticated);
        }
        Ok(())
    }
}
