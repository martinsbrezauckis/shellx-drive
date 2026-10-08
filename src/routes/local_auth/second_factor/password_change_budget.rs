use chrono::Utc;

use crate::{error::ApiResult, server::AppState, storage::AuthAttemptAdmission};

const PASSWORD_CHANGE_TOTP_CLIENT_SCOPE: &str = "password_change_totp";
const PASSWORD_CHANGE_TOTP_ACCOUNT_SCOPE: &str = "password_change_totp_account";
const PASSWORD_CHANGE_TOTP_ACCOUNT_PARTITION: &str = "account";
const PASSWORD_CHANGE_TOTP_ACCOUNT_RECOVERY_SCOPE: &str = "password_change_totp_account_recovery";
const PASSWORD_CHANGE_TOTP_ACCOUNT_RECOVERY_PARTITION: &str = "recovery";

/// Password changes require an independent shared budget from sign-in. A
/// valid sign-in factor should not clear a concurrent password-change guess,
/// but both flows retain their own per-client limits and one-shot recovery.
pub(crate) fn ensure_password_change_totp_not_locked(
    state: &AppState,
    email: &str,
    client_fingerprint: &str,
) -> ApiResult<AuthAttemptAdmission> {
    state.storage.ensure_auth_attempt_not_locked(
        Some(email),
        PASSWORD_CHANGE_TOTP_CLIENT_SCOPE,
        client_fingerprint,
        Utc::now().timestamp(),
    )?;
    state.storage.admit_auth_attempt_or_reserve_shared_recovery(
        Some(email),
        PASSWORD_CHANGE_TOTP_ACCOUNT_SCOPE,
        PASSWORD_CHANGE_TOTP_ACCOUNT_PARTITION,
        PASSWORD_CHANGE_TOTP_ACCOUNT_RECOVERY_SCOPE,
        PASSWORD_CHANGE_TOTP_ACCOUNT_RECOVERY_PARTITION,
    )
}

pub(crate) fn record_password_change_totp_failure(
    state: &AppState,
    email: &str,
    client_fingerprint: &str,
    admission: AuthAttemptAdmission,
) -> ApiResult<()> {
    super::super::record_auth_failure(
        state,
        email,
        PASSWORD_CHANGE_TOTP_CLIENT_SCOPE,
        client_fingerprint,
    )?;
    if admission == AuthAttemptAdmission::Ordinary {
        super::super::record_auth_failure(
            state,
            email,
            PASSWORD_CHANGE_TOTP_ACCOUNT_SCOPE,
            PASSWORD_CHANGE_TOTP_ACCOUNT_PARTITION,
        )?;
    }
    Ok(())
}

pub(crate) fn clear_password_change_totp_failures(
    state: &AppState,
    email: &str,
    client_fingerprint: &str,
) -> ApiResult<()> {
    state.storage.clear_auth_attempt(
        Some(email),
        PASSWORD_CHANGE_TOTP_CLIENT_SCOPE,
        client_fingerprint,
    )?;
    state.storage.clear_shared_auth_attempt_and_recovery(
        Some(email),
        PASSWORD_CHANGE_TOTP_ACCOUNT_SCOPE,
        PASSWORD_CHANGE_TOTP_ACCOUNT_PARTITION,
        PASSWORD_CHANGE_TOTP_ACCOUNT_RECOVERY_SCOPE,
        PASSWORD_CHANGE_TOTP_ACCOUNT_RECOVERY_PARTITION,
    )
}
