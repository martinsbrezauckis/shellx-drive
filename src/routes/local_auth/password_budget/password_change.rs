use chrono::Utc;

use crate::{error::ApiResult, server::AppState, storage::AuthAttemptAdmission};

const CLIENT_SCOPE: &str = "password_change";
const ACCOUNT_SCOPE: &str = "password_change_account";
const ACCOUNT_PARTITION: &str = "account";
const ACCOUNT_RECOVERY_SCOPE: &str = "password_change_account_recovery";
const ACCOUNT_RECOVERY_PARTITION: &str = "recovery";

/// Keep the existing per-client password-change throttle, but add a durable
/// account-wide penalty so rotating clients cannot make current-password
/// guessing unlimited for a stolen session.
pub(crate) fn ensure_password_change_not_locked(
    state: &AppState,
    email: &str,
    client_fingerprint: &str,
) -> ApiResult<AuthAttemptAdmission> {
    state.storage.ensure_auth_attempt_not_locked(
        Some(email),
        CLIENT_SCOPE,
        client_fingerprint,
        Utc::now().timestamp(),
    )?;
    state.storage.admit_auth_attempt_or_reserve_shared_recovery(
        Some(email),
        ACCOUNT_SCOPE,
        ACCOUNT_PARTITION,
        ACCOUNT_RECOVERY_SCOPE,
        ACCOUNT_RECOVERY_PARTITION,
    )
}

pub(crate) fn record_password_change_failure(
    state: &AppState,
    email: &str,
    client_fingerprint: &str,
    admission: AuthAttemptAdmission,
) -> ApiResult<()> {
    super::super::record_auth_failure(state, email, CLIENT_SCOPE, client_fingerprint)?;
    if admission == AuthAttemptAdmission::Ordinary {
        super::super::record_auth_failure(state, email, ACCOUNT_SCOPE, ACCOUNT_PARTITION)?;
    }
    Ok(())
}

pub(crate) fn clear_password_change_failures(
    state: &AppState,
    email: &str,
    client_fingerprint: &str,
) -> ApiResult<()> {
    state
        .storage
        .clear_auth_attempt(Some(email), CLIENT_SCOPE, client_fingerprint)?;
    state.storage.clear_shared_auth_attempt_and_recovery(
        Some(email),
        ACCOUNT_SCOPE,
        ACCOUNT_PARTITION,
        ACCOUNT_RECOVERY_SCOPE,
        ACCOUNT_RECOVERY_PARTITION,
    )
}
