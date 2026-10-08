use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::error::{ApiError, ApiResult};

use super::super::{auth_attempt_key, enforce_auth_attempt_row_cap_locked, Storage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthAttemptAdmission {
    Ordinary,
    SharedRecovery,
}

impl Storage {
    /// Admit a normal verification when the shared account row is open, or
    /// reserve exactly one verifier pass while that row is locked. The
    /// reservation expires with the current shared penalty and never updates
    /// that penalty, so rejected callers cannot prolong it.
    pub(crate) fn admit_auth_attempt_or_reserve_shared_recovery(
        &self,
        actor_email: Option<&str>,
        shared_scope: &str,
        shared_partition: &str,
        recovery_scope: &str,
        recovery_partition: &str,
    ) -> ApiResult<AuthAttemptAdmission> {
        let shared_key = auth_attempt_key(actor_email, shared_scope, Some(shared_partition));
        let recovery_key = auth_attempt_key(actor_email, recovery_scope, Some(recovery_partition));
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let actor = actor_email.map(str::to_string);
        let conn = self.conn.lock().unwrap();
        let shared_locked_until = conn
            .query_row(
                "SELECT locked_until FROM auth_attempts WHERE key = ?1",
                params![&shared_key],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        let Some(shared_locked_until) = shared_locked_until else {
            return Ok(AuthAttemptAdmission::Ordinary);
        };
        let shared_locked_until = DateTime::parse_from_rfc3339(&shared_locked_until)
            .map_err(|_| ApiError::TooManyRequests)?
            .with_timezone(&Utc);
        if shared_locked_until <= now {
            return Ok(AuthAttemptAdmission::Ordinary);
        }

        let recovery_locked_until = conn
            .query_row(
                "SELECT locked_until FROM auth_attempts WHERE key = ?1",
                params![&recovery_key],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .map(|value| {
                DateTime::parse_from_rfc3339(&value)
                    .map(|value| value.with_timezone(&Utc))
                    .map_err(|_| ApiError::TooManyRequests)
            })
            .transpose()?;
        if recovery_locked_until.is_some_and(|until| until >= shared_locked_until) {
            return Err(ApiError::TooManyRequests);
        }

        conn.execute(
            "INSERT INTO auth_attempts (
                key, actor_email, client_fingerprint, scope, failures, locked_until, updated_at
             ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)
             ON CONFLICT(key) DO UPDATE SET
                actor_email = excluded.actor_email,
                client_fingerprint = excluded.client_fingerprint,
                scope = excluded.scope,
                failures = 1,
                locked_until = excluded.locked_until,
                updated_at = excluded.updated_at",
            params![
                &recovery_key,
                actor.as_deref(),
                recovery_partition,
                recovery_scope,
                shared_locked_until.to_rfc3339(),
                &now_text,
            ],
        )?;
        enforce_auth_attempt_row_cap_locked(&conn)?;
        Ok(AuthAttemptAdmission::SharedRecovery)
    }

    pub(crate) fn clear_shared_auth_attempt_and_recovery(
        &self,
        actor_email: Option<&str>,
        shared_scope: &str,
        shared_partition: &str,
        recovery_scope: &str,
        recovery_partition: &str,
    ) -> ApiResult<()> {
        let shared_key = auth_attempt_key(actor_email, shared_scope, Some(shared_partition));
        let recovery_key = auth_attempt_key(actor_email, recovery_scope, Some(recovery_partition));
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM auth_attempts WHERE key IN (?1, ?2)",
            params![&shared_key, &recovery_key],
        )?;
        tx.commit()?;
        Ok(())
    }
}
