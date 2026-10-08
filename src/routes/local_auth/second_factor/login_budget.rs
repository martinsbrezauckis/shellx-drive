use chrono::Utc;

use crate::{error::ApiResult, server::AppState, storage::AuthAttemptAdmission};

const TOTP_LOGIN_CLIENT_SCOPE: &str = "totp";
const TOTP_LOGIN_ACCOUNT_SCOPE: &str = "totp_login_account";
const TOTP_LOGIN_ACCOUNT_PARTITION: &str = "account";
const TOTP_LOGIN_ACCOUNT_RECOVERY_SCOPE: &str = "totp_login_account_recovery";
const TOTP_LOGIN_ACCOUNT_RECOVERY_PARTITION: &str = "recovery";

pub(crate) fn ensure_totp_login_not_locked(
    state: &AppState,
    email: &str,
    client_fingerprint: &str,
) -> ApiResult<AuthAttemptAdmission> {
    state.storage.ensure_auth_attempt_not_locked(
        Some(email),
        TOTP_LOGIN_CLIENT_SCOPE,
        client_fingerprint,
        Utc::now().timestamp(),
    )?;
    state.storage.admit_auth_attempt_or_reserve_shared_recovery(
        Some(email),
        TOTP_LOGIN_ACCOUNT_SCOPE,
        TOTP_LOGIN_ACCOUNT_PARTITION,
        TOTP_LOGIN_ACCOUNT_RECOVERY_SCOPE,
        TOTP_LOGIN_ACCOUNT_RECOVERY_PARTITION,
    )
}

pub(crate) fn record_totp_login_failure(
    state: &AppState,
    email: &str,
    client_fingerprint: &str,
    admission: AuthAttemptAdmission,
) -> ApiResult<()> {
    super::super::record_auth_failure(state, email, TOTP_LOGIN_CLIENT_SCOPE, client_fingerprint)?;
    if admission == AuthAttemptAdmission::Ordinary {
        super::super::record_auth_failure(
            state,
            email,
            TOTP_LOGIN_ACCOUNT_SCOPE,
            TOTP_LOGIN_ACCOUNT_PARTITION,
        )?;
    }
    Ok(())
}

pub(crate) fn clear_totp_login_failures(
    state: &AppState,
    email: &str,
    client_fingerprint: &str,
) -> ApiResult<()> {
    state
        .storage
        .clear_auth_attempt(Some(email), TOTP_LOGIN_CLIENT_SCOPE, client_fingerprint)?;
    state.storage.clear_shared_auth_attempt_and_recovery(
        Some(email),
        TOTP_LOGIN_ACCOUNT_SCOPE,
        TOTP_LOGIN_ACCOUNT_PARTITION,
        TOTP_LOGIN_ACCOUNT_RECOVERY_SCOPE,
        TOTP_LOGIN_ACCOUNT_RECOVERY_PARTITION,
    )
}
