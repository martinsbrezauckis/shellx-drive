//! Authentication throttling, lockouts, and public rate-limit counters.

use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{AuthAttemptDebug, Receipt},
};

use super::{
    auth_attempt_key, authorization, enforce_auth_attempt_row_cap_locked, insert_receipt_rows,
    new_receipt, prune_auth_attempts_locked, row_to_auth_attempt, AuthThrottlePolicy, Storage,
};

mod fixed_window;
mod public_capability;
mod shared_recovery;

pub(crate) use public_capability::{
    clear_public_capability_password_budget_in_tx, PublicCapabilityKind,
    PublicPasswordAttemptResult,
};
pub(crate) use shared_recovery::AuthAttemptAdmission;

impl Storage {
    pub fn ensure_auth_attempt_not_locked(
        &self,
        actor_email: Option<&str>,
        scope: &str,
        client_fingerprint: &str,
        now_epoch: i64,
    ) -> ApiResult<()> {
        let key = auth_attempt_key(actor_email, scope, Some(client_fingerprint));
        let conn = self.conn.lock().unwrap();
        let locked_until = conn
            .query_row(
                "SELECT locked_until FROM auth_attempts WHERE key = ?1",
                params![key],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        let Some(locked_until) = locked_until else {
            return Ok(());
        };
        let locked_until = DateTime::parse_from_rfc3339(&locked_until)
            .map_err(|_| ApiError::TooManyRequests)?
            .timestamp();
        if locked_until > now_epoch {
            return Err(ApiError::TooManyRequests);
        }
        Ok(())
    }

    pub fn record_auth_attempt_failure(
        &self,
        actor_email: Option<&str>,
        scope: &str,
        client_fingerprint: &str,
        policy: AuthThrottlePolicy,
    ) -> ApiResult<AuthAttemptDebug> {
        let now = Utc::now();
        let conn = self.conn.lock().unwrap();
        record_auth_attempt_failure_locked(
            &conn,
            actor_email,
            scope,
            client_fingerprint,
            policy,
            now,
        )
    }

    pub fn consume_public_rate_limit(
        &self,
        scope: &str,
        limit: i64,
        window_seconds: i64,
    ) -> ApiResult<()> {
        let limit = limit.max(1);
        let window_seconds = window_seconds.max(1);
        let key = auth_attempt_key(None, scope, None);
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let window_start = now - Duration::seconds(window_seconds);
        let conn = self.conn.lock().unwrap();
        prune_auth_attempts_locked(&conn, &now_text)?;
        let existing = conn
            .query_row(
                "SELECT failures, updated_at FROM auth_attempts WHERE key = ?1",
                params![&key],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let previous_failures = existing
            .as_ref()
            .and_then(|(failures, updated_at)| {
                DateTime::parse_from_rfc3339(updated_at)
                    .ok()
                    .filter(|updated_at| updated_at.with_timezone(&Utc) > window_start)
                    .map(|_| *failures)
            })
            .unwrap_or(0);
        let attempts = previous_failures + 1;
        let locked_until = if attempts > limit {
            Some((now + Duration::seconds(window_seconds)).to_rfc3339())
        } else {
            None
        };
        conn.execute(
            "INSERT INTO auth_attempts (
                key, actor_email, scope, failures, locked_until, updated_at
             ) VALUES (?1, NULL, ?2, ?3, ?4, ?5)
             ON CONFLICT(key) DO UPDATE SET
                actor_email = NULL,
                scope = excluded.scope,
                failures = excluded.failures,
                locked_until = excluded.locked_until,
                updated_at = excluded.updated_at",
            params![&key, scope, attempts, locked_until, &now_text],
        )?;
        enforce_auth_attempt_row_cap_locked(&conn)?;
        if attempts > limit {
            return Err(ApiError::TooManyRequests);
        }
        Ok(())
    }

    pub fn clear_auth_attempt(
        &self,
        actor_email: Option<&str>,
        scope: &str,
        client_fingerprint: &str,
    ) -> ApiResult<()> {
        let key = auth_attempt_key(actor_email, scope, Some(client_fingerprint));
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM auth_attempts WHERE key = ?1", params![key])?;
        Ok(())
    }

    pub fn unlock_auth_attempt(
        &self,
        key: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        let key = key.trim();
        if key.is_empty() || key.len() > 512 {
            return Err(ApiError::Validation(
                "attempt key must be between 1 and 512 characters".to_string(),
            ));
        }
        let receipt = new_receipt("auth.attempt.unlock", &actor.email, Some(key));
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        if tx.execute("DELETE FROM auth_attempts WHERE key = ?1", params![key])? == 0 {
            return Err(ApiError::NotFound);
        }
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }

    pub fn list_auth_attempts(&self) -> ApiResult<Vec<AuthAttemptDebug>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT key, actor_email, client_fingerprint, scope, failures, locked_until, updated_at
             FROM auth_attempts ORDER BY updated_at DESC, key ASC",
        )?;
        let rows = stmt.query_map([], row_to_auth_attempt)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_auth_attempts_bounded(&self, limit: usize) -> ApiResult<Vec<AuthAttemptDebug>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT key, actor_email, client_fingerprint, scope, failures, locked_until, updated_at
             FROM auth_attempts ORDER BY updated_at DESC, key ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(
            [i64::try_from(limit).unwrap_or(i64::MAX)],
            row_to_auth_attempt,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

pub(super) fn record_auth_attempt_failure_locked(
    conn: &rusqlite::Connection,
    actor_email: Option<&str>,
    scope: &str,
    client_fingerprint: &str,
    policy: AuthThrottlePolicy,
    now: DateTime<Utc>,
) -> ApiResult<AuthAttemptDebug> {
    let key = auth_attempt_key(actor_email, scope, Some(client_fingerprint));
    let now_text = now.to_rfc3339();
    let actor = actor_email.map(str::to_string);
    prune_auth_attempts_locked(conn, &now_text)?;
    let existing = conn
        .query_row(
            "SELECT failures, updated_at FROM auth_attempts WHERE key = ?1",
            params![&key],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let decay_start = now - Duration::seconds(policy.decay_seconds.max(1));
    let previous_failures = existing
        .and_then(|(failures, updated_at)| {
            DateTime::parse_from_rfc3339(&updated_at)
                .ok()
                .filter(|updated_at| updated_at.with_timezone(&Utc) > decay_start)
                .map(|_| failures)
        })
        .unwrap_or(0);
    let threshold = policy.threshold.max(1);
    let failures = (previous_failures + 1).min(threshold + 16);
    let locked_until = if failures >= threshold {
        let exponent = (failures - threshold).clamp(0, 16) as u32;
        let multiplier = 1_i64.checked_shl(exponent).unwrap_or(i64::MAX);
        let base = policy.base_lockout_seconds.max(1);
        let maximum = policy.max_lockout_seconds.max(base);
        let seconds = base.saturating_mul(multiplier).min(maximum);
        Some((now + Duration::seconds(seconds)).to_rfc3339())
    } else {
        None
    };
    conn.execute(
        "INSERT INTO auth_attempts (
            key, actor_email, client_fingerprint, scope, failures, locked_until, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(key) DO UPDATE SET actor_email = excluded.actor_email,
            client_fingerprint = excluded.client_fingerprint, scope = excluded.scope,
            failures = excluded.failures, locked_until = excluded.locked_until,
            updated_at = excluded.updated_at",
        params![
            &key,
            actor.as_deref(),
            client_fingerprint,
            scope,
            failures,
            locked_until,
            &now_text
        ],
    )?;
    enforce_auth_attempt_row_cap_locked(conn)?;
    Ok(AuthAttemptDebug {
        key,
        actor_email: actor,
        client_fingerprint: Some(client_fingerprint.to_string()),
        scope: scope.to_string(),
        failures,
        locked_until,
        updated_at: now_text,
    })
}
