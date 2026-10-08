use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use crate::{
    error::{ApiError, ApiResult},
    storage::Storage,
};

use super::{password_resource_ref, PublicCapabilityKind};
use crate::storage::{
    auth_attempt_key, enforce_auth_attempt_row_cap_locked, prune_auth_attempts_locked,
};

pub(super) const PASSWORD_WORK_CLIENT_LIMIT: i64 = 10;
pub(super) const PASSWORD_WORK_CAPABILITY_LIMIT: i64 = 30;
const PASSWORD_WORK_WINDOW_SECONDS: i64 = 60;

impl PublicCapabilityKind {
    pub(super) fn work_client_scope(self) -> &'static str {
        match self {
            Self::Share => "share_password_work",
            Self::Drop => "drop_password_work",
        }
    }

    pub(super) fn work_shared_scope(self) -> &'static str {
        match self {
            Self::Share => "share_password_work_capability",
            Self::Drop => "drop_password_work_capability",
        }
    }
}

impl Storage {
    /// Reserve one expensive public password verification before an Argon2
    /// worker permit is acquired. Correct passwords cannot clear this budget.
    pub(crate) fn reserve_public_capability_password_work(
        &self,
        kind: PublicCapabilityKind,
        capability_id: &str,
        client_fingerprint: &str,
    ) -> ApiResult<()> {
        let resource_ref = password_resource_ref(kind, capability_id);
        let now = Utc::now();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        prune_auth_attempts_locked(&tx, &now.to_rfc3339())?;
        consume_fixed_window_in_tx(
            &tx,
            &resource_ref,
            kind.work_client_scope(),
            client_fingerprint,
            PASSWORD_WORK_CLIENT_LIMIT,
            PASSWORD_WORK_WINDOW_SECONDS,
            now,
        )?;
        consume_fixed_window_in_tx(
            &tx,
            &resource_ref,
            kind.work_shared_scope(),
            "capability",
            PASSWORD_WORK_CAPABILITY_LIMIT,
            PASSWORD_WORK_WINDOW_SECONDS,
            now,
        )?;
        enforce_auth_attempt_row_cap_locked(&tx)?;
        tx.commit()?;
        Ok(())
    }
}

fn consume_fixed_window_in_tx(
    tx: &Transaction<'_>,
    resource_ref: &str,
    scope: &str,
    partition: &str,
    limit: i64,
    window_seconds: i64,
    now: DateTime<Utc>,
) -> ApiResult<()> {
    let key = auth_attempt_key(Some(resource_ref), scope, Some(partition));
    let window_start = now - Duration::seconds(window_seconds);
    let active = tx
        .query_row(
            "SELECT failures, updated_at FROM auth_attempts WHERE key = ?1",
            params![&key],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .and_then(|(attempts, updated_at)| {
            DateTime::parse_from_rfc3339(&updated_at)
                .ok()
                .map(|started| (attempts, started.with_timezone(&Utc)))
                .filter(|(_, started)| *started > window_start)
        });
    if active
        .as_ref()
        .is_some_and(|(attempts, _)| *attempts >= limit)
    {
        return Err(ApiError::TooManyRequests);
    }

    let (attempts, started_at) = active
        .map(|(attempts, started)| (attempts.saturating_add(1), started))
        .unwrap_or((1, now));
    let locked_until =
        (attempts >= limit).then(|| (started_at + Duration::seconds(window_seconds)).to_rfc3339());
    tx.execute(
        "INSERT INTO auth_attempts (
            key, actor_email, client_fingerprint, scope, failures, locked_until, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(key) DO UPDATE SET
            actor_email = excluded.actor_email,
            client_fingerprint = excluded.client_fingerprint,
            scope = excluded.scope,
            failures = excluded.failures,
            locked_until = excluded.locked_until,
            updated_at = excluded.updated_at",
        params![
            key,
            resource_ref,
            partition,
            scope,
            attempts,
            locked_until,
            started_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}
