use chrono::Utc;
use rusqlite::{params, Transaction, TransactionBehavior};

use crate::{auth::token_hash, error::ApiResult, storage::AuthThrottlePolicy};

use super::{record_auth_attempt_failure_locked, AuthAttemptAdmission};
use crate::storage::Storage;

mod work_budget;

const CLIENT_POLICY: AuthThrottlePolicy = AuthThrottlePolicy {
    threshold: 5,
    base_lockout_seconds: 30,
    max_lockout_seconds: 300,
    decay_seconds: 900,
};

const CAPABILITY_POLICY: AuthThrottlePolicy = AuthThrottlePolicy {
    threshold: 20,
    base_lockout_seconds: 30,
    max_lockout_seconds: 300,
    decay_seconds: 900,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicCapabilityKind {
    Share,
    Drop,
}

impl PublicCapabilityKind {
    fn label(self) -> &'static str {
        match self {
            Self::Share => "share",
            Self::Drop => "drop",
        }
    }

    fn client_scope(self) -> &'static str {
        match self {
            Self::Share => "share_password",
            Self::Drop => "drop_password",
        }
    }

    fn shared_scope(self) -> &'static str {
        match self {
            Self::Share => "share_password_capability",
            Self::Drop => "drop_password_capability",
        }
    }

    fn recovery_scope(self) -> &'static str {
        match self {
            Self::Share => "share_password_recovery",
            Self::Drop => "drop_password_recovery",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicPasswordAttemptResult {
    pub(crate) locked_out: bool,
}

impl Storage {
    /// Admit one verifier while the process-wide public password permit is
    /// held. Different client partitions therefore cannot race the durable
    /// capability row on the supported single-process server.
    pub(crate) fn admit_public_capability_password_attempt(
        &self,
        kind: PublicCapabilityKind,
        capability_id: &str,
        client_fingerprint: &str,
    ) -> ApiResult<AuthAttemptAdmission> {
        let resource_ref = password_resource_ref(kind, capability_id);
        self.ensure_auth_attempt_not_locked(
            Some(&resource_ref),
            kind.client_scope(),
            client_fingerprint,
            Utc::now().timestamp(),
        )?;
        self.admit_auth_attempt_or_reserve_shared_recovery(
            Some(&resource_ref),
            kind.shared_scope(),
            "capability",
            kind.recovery_scope(),
            "recovery",
        )
    }

    /// Persist both the client and capability result before releasing the
    /// verifier permit. Success clears the shared gate and the verifying
    /// client, preserving other clients' individual lock/audit evidence. A
    /// recovery pass never extends an active shared penalty.
    pub(crate) fn complete_public_capability_password_attempt(
        &self,
        kind: PublicCapabilityKind,
        capability_id: &str,
        client_fingerprint: &str,
        admission: AuthAttemptAdmission,
        verified: bool,
    ) -> ApiResult<PublicPasswordAttemptResult> {
        let resource_ref = password_resource_ref(kind, capability_id);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if verified {
            clear_verified_password_attempt_in_tx(&tx, kind, &resource_ref, client_fingerprint)?;
            tx.commit()?;
            return Ok(PublicPasswordAttemptResult { locked_out: false });
        }

        let now = Utc::now();
        let client = record_auth_attempt_failure_locked(
            &tx,
            Some(&resource_ref),
            kind.client_scope(),
            client_fingerprint,
            CLIENT_POLICY,
            now,
        )?;
        let shared = if admission == AuthAttemptAdmission::Ordinary {
            Some(record_auth_attempt_failure_locked(
                &tx,
                Some(&resource_ref),
                kind.shared_scope(),
                "capability",
                CAPABILITY_POLICY,
                now,
            )?)
        } else {
            None
        };
        tx.commit()?;
        Ok(PublicPasswordAttemptResult {
            locked_out: client.locked_until.is_some()
                || shared.is_some_and(|attempt| attempt.locked_until.is_some()),
        })
    }
}

pub(crate) fn clear_public_capability_password_budget_in_tx(
    tx: &Transaction<'_>,
    kind: PublicCapabilityKind,
    capability_id: &str,
) -> ApiResult<()> {
    let resource_ref = password_resource_ref(kind, capability_id);
    tx.execute(
        "DELETE FROM auth_attempts
         WHERE actor_email = ?1 AND scope IN (?2, ?3, ?4, ?5, ?6)",
        params![
            resource_ref,
            kind.client_scope(),
            kind.shared_scope(),
            kind.recovery_scope(),
            kind.work_client_scope(),
            kind.work_shared_scope()
        ],
    )?;
    Ok(())
}

fn clear_verified_password_attempt_in_tx(
    tx: &Transaction<'_>,
    kind: PublicCapabilityKind,
    resource_ref: &str,
    client_fingerprint: &str,
) -> ApiResult<()> {
    tx.execute(
        "DELETE FROM auth_attempts
         WHERE actor_email = ?1
           AND (scope IN (?2, ?3)
                OR (scope = ?4 AND client_fingerprint = ?5))",
        params![
            resource_ref,
            kind.shared_scope(),
            kind.recovery_scope(),
            kind.client_scope(),
            client_fingerprint
        ],
    )?;
    Ok(())
}

fn password_resource_ref(kind: PublicCapabilityKind, capability_id: &str) -> String {
    token_hash(&format!(
        "public-capability-password-v1\0{}\0{capability_id}",
        kind.label()
    ))
}

#[cfg(test)]
mod tests;
