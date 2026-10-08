use chrono::Utc;

use crate::{error::ApiResult, server::AppState, storage::AuthAttemptAdmission};

const CLIENT_SCOPE: &str = "password";
const ACCOUNT_SCOPE: &str = "password_login_account";
const ACCOUNT_PARTITION: &str = "account";
const ACCOUNT_RECOVERY_SCOPE: &str = "password_login_account_recovery";
const ACCOUNT_RECOVERY_PARTITION: &str = "recovery";

pub(crate) fn ensure_password_login_not_locked(
    state: &AppState,
    throttle_actor: &str,
    client_fingerprint: &str,
) -> ApiResult<AuthAttemptAdmission> {
    let now = Utc::now().timestamp();
    state.storage.ensure_auth_attempt_not_locked(
        Some(throttle_actor),
        CLIENT_SCOPE,
        client_fingerprint,
        now,
    )?;
    state.storage.admit_auth_attempt_or_reserve_shared_recovery(
        Some(throttle_actor),
        ACCOUNT_SCOPE,
        ACCOUNT_PARTITION,
        ACCOUNT_RECOVERY_SCOPE,
        ACCOUNT_RECOVERY_PARTITION,
    )
}

pub(crate) fn record_password_login_failure(
    state: &AppState,
    throttle_actor: &str,
    client_fingerprint: &str,
    admission: AuthAttemptAdmission,
) -> ApiResult<()> {
    super::super::record_auth_failure(state, throttle_actor, CLIENT_SCOPE, client_fingerprint)?;
    if admission == AuthAttemptAdmission::Ordinary {
        super::super::record_auth_failure(state, throttle_actor, ACCOUNT_SCOPE, ACCOUNT_PARTITION)?;
    }
    Ok(())
}

pub(crate) fn clear_password_login_failures(
    state: &AppState,
    throttle_actor: &str,
    client_fingerprint: &str,
) -> ApiResult<()> {
    state
        .storage
        .clear_auth_attempt(Some(throttle_actor), CLIENT_SCOPE, client_fingerprint)?;
    state.storage.clear_shared_auth_attempt_and_recovery(
        Some(throttle_actor),
        ACCOUNT_SCOPE,
        ACCOUNT_PARTITION,
        ACCOUNT_RECOVERY_SCOPE,
        ACCOUNT_RECOVERY_PARTITION,
    )
}
