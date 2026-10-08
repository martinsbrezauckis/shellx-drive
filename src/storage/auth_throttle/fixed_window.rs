use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension};

use crate::error::{ApiError, ApiResult};

use super::{
    auth_attempt_key, enforce_auth_attempt_row_cap_locked, prune_auth_attempts_locked, Storage,
};

impl Storage {
    /// Consume a fixed-window budget whose denied calls cannot move the
    /// window forward. This is appropriate for account-recovery issuance:
    /// anonymous traffic may cause one bounded cooldown, but cannot keep the
    /// account locked forever by refreshing `updated_at` while over limit.
    pub fn consume_partitioned_fixed_window_rate_limit(
        &self,
        resource_id: &str,
        scope: &str,
        client_fingerprint: &str,
        limit: i64,
        window_seconds: i64,
    ) -> ApiResult<()> {
        let limit = limit.max(1);
        let window_seconds = window_seconds.max(1);
        let key = auth_attempt_key(Some(resource_id), scope, Some(client_fingerprint));
        if self.public_rate_limit_denials.denies(&key) {
            return Err(ApiError::TooManyRequests);
        }
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let window_start = now - Duration::seconds(window_seconds);
        let conn = self.conn.lock().unwrap();
        let existing = conn
            .query_row(
                "SELECT failures, updated_at FROM auth_attempts WHERE key = ?1",
                params![&key],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let active = existing.and_then(|(attempts, updated_at)| {
            DateTime::parse_from_rfc3339(&updated_at)
                .ok()
                .map(|started| (attempts, started.with_timezone(&Utc)))
                .filter(|(_, started)| *started > window_start)
        });
        if active
            .as_ref()
            .is_some_and(|(attempts, _)| *attempts >= limit)
        {
            let remaining = active
                .as_ref()
                .map(|(_, started)| *started + Duration::seconds(window_seconds) - now)
                .and_then(|remaining| remaining.to_std().ok())
                .unwrap_or_default();
            drop(conn);
            self.public_rate_limit_denials.deny_for(&key, remaining);
            return Err(ApiError::TooManyRequests);
        }

        let (attempts, started_at) = active
            .map(|(attempts, started)| (attempts.saturating_add(1), started))
            .unwrap_or((1, now));
        let locked_until = (attempts >= limit)
            .then(|| (started_at + Duration::seconds(window_seconds)).to_rfc3339());
        prune_auth_attempts_locked(&conn, &now_text)?;
        conn.execute(
            "INSERT INTO auth_attempts (
                key, actor_email, client_fingerprint, scope, failures, locked_until, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(key) DO UPDATE SET
                actor_email = excluded.actor_email,
                client_fingerprint = excluded.client_fingerprint,
                scope = excluded.scope,
                failures = excluded.failures,
                locked_until = excluded.locked_until,
                updated_at = CASE
                    WHEN auth_attempts.updated_at > ?8 THEN auth_attempts.updated_at
                    ELSE excluded.updated_at
                END",
            params![
                &key,
                resource_id,
                client_fingerprint,
                scope,
                attempts,
                locked_until,
                &now_text,
                window_start.to_rfc3339(),
            ],
        )?;
        enforce_auth_attempt_row_cap_locked(&conn)?;
        Ok(())
    }
}
