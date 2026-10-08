use chrono::Utc;

use crate::{
    auth::{matched_totp_counter, recovery_code_hash},
    error::{ApiError, ApiResult},
    model::AuthAccountSecret,
    server::AppState,
    storage::VerifiedLocalSecondFactor,
};

const TOTP_SECURITY_MUTATION_SCOPE: &str = "totp_security_mutation_factor";

mod login_budget;
mod password_change_budget;

pub(super) use login_budget::{
    clear_totp_login_failures, ensure_totp_login_not_locked, record_totp_login_failure,
};
pub(super) use password_change_budget::{
    clear_password_change_totp_failures, ensure_password_change_totp_not_locked,
    record_password_change_totp_failure,
};

pub(super) struct ValidatedSecondFactor {
    pub(super) account: AuthAccountSecret,
    pub(super) credential: VerifiedLocalSecondFactor,
}

pub(super) fn validate_second_factor_evidence(
    state: &AppState,
    email: &str,
    totp_code: Option<&str>,
    recovery_code: Option<&str>,
    consume_recovery: bool,
) -> ApiResult<ValidatedSecondFactor> {
    let account = state
        .storage
        .get_auth_account_secret(email)?
        .ok_or(ApiError::Unauthenticated)?;
    let Some(secret) = account.totp_secret.as_deref() else {
        return Err(ApiError::Validation(
            "2FA setup has not been started".to_string(),
        ));
    };
    if let Some(code) = totp_code {
        if let Some(counter) = matched_totp_counter(secret, code, Utc::now().timestamp()) {
            return Ok(ValidatedSecondFactor {
                account,
                credential: VerifiedLocalSecondFactor::TotpCounter(counter),
            });
        }
    }
    if let Some(code) = recovery_code {
        let hash = recovery_code_hash(code);
        if consume_recovery
            && account
                .recovery_code_hashes
                .iter()
                .any(|stored| stored == &hash)
        {
            return Ok(ValidatedSecondFactor {
                account,
                credential: VerifiedLocalSecondFactor::RecoveryCode(hash),
            });
        }
    }
    Err(ApiError::Unauthenticated)
}

pub(super) fn validate_second_factor_throttled(
    state: &AppState,
    email: &str,
    totp_code: Option<&str>,
    recovery_code: Option<&str>,
    consume_recovery: bool,
    client_fingerprint: &str,
) -> ApiResult<ValidatedSecondFactor> {
    state.storage.ensure_auth_attempt_not_locked(
        Some(email),
        TOTP_SECURITY_MUTATION_SCOPE,
        client_fingerprint,
        Utc::now().timestamp(),
    )?;
    match validate_second_factor_evidence(state, email, totp_code, recovery_code, consume_recovery)
    {
        Ok(validated) => {
            state.storage.clear_auth_attempt(
                Some(email),
                TOTP_SECURITY_MUTATION_SCOPE,
                client_fingerprint,
            )?;
            Ok(validated)
        }
        Err(error) => {
            super::record_auth_failure(
                state,
                email,
                TOTP_SECURITY_MUTATION_SCOPE,
                client_fingerprint,
            )?;
            Err(error)
        }
    }
}
