use chrono::Utc;
use rusqlite::{params, OptionalExtension};

use crate::{
    auth::constant_time_str_eq,
    error::{ApiError, ApiResult},
    model::{AuthAccountSecret, AuthSession},
    storage::{auth_security, Storage, VerifiedLocalSecondFactor},
};

impl Storage {
    /// Insert a local-password session only if the exact password and 2FA state
    /// which the route verified is still current. A matched TOTP counter is
    /// consumed in this same write transaction so concurrent replays cannot
    /// mint another session.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_verified_local_auth_session(
        &self,
        id: &str,
        expected_account: &AuthAccountSecret,
        second_factor: VerifiedLocalSecondFactor,
        issuer: &str,
        token_hash: &str,
        expires_at: &str,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> ApiResult<AuthSession> {
        let session = AuthSession {
            id: id.to_string(),
            actor_email: expected_account.email.clone(),
            issuer: issuer.to_string(),
            subject: expected_account.user_id.clone(),
            expires_at: expires_at.to_string(),
            revoked_at: None,
            created_at: Utc::now().to_rfc3339(),
            revoked: false,
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (current, last_used_totp_counter) = tx
            .query_row(
                "SELECT user_id, email, password_hash, is_admin, totp_secret,
                        totp_enabled, recovery_code_hashes, disabled_at, security_version,
                        totp_last_used_counter
                 FROM auth_accounts WHERE email = ?1",
                params![&expected_account.email],
                |row| {
                    Ok((
                        super::super::row_to_auth_account_secret(row)?,
                        row.get::<_, Option<i64>>(9)?,
                    ))
                },
            )
            .optional()?
            .ok_or(ApiError::Unauthenticated)?;
        let security_state_matches = current.user_id == expected_account.user_id
            && constant_time_str_eq(&current.password_hash, &expected_account.password_hash)
            && current.is_admin == expected_account.is_admin
            && current.totp_secret == expected_account.totp_secret
            && current.totp_enabled == expected_account.totp_enabled
            && current.security_version == expected_account.security_version
            && current.disabled_at.is_none()
            && expected_account.disabled_at.is_none();
        if !security_state_matches {
            return Err(ApiError::Unauthenticated);
        }
        match (current.totp_enabled, second_factor) {
            (false, VerifiedLocalSecondFactor::NotRequired) => {}
            (true, VerifiedLocalSecondFactor::TotpCounter(counter)) => {
                if last_used_totp_counter.is_some_and(|last_used| counter <= last_used) {
                    return Err(ApiError::Unauthenticated);
                }
                auth_security::consume_totp_counter_in_tx(&tx, &expected_account.email, counter)?;
            }
            (true, VerifiedLocalSecondFactor::RecoveryCode(hash)) => {
                auth_security::consume_recovery_code_in_tx(&tx, &expected_account.email, &hash)?;
            }
            _ => {
                return Err(ApiError::Unauthenticated);
            }
        }
        super::insert_auth_session_with_client_in_tx(
            &tx, &session, token_hash, client_ip, user_agent,
        )?;
        tx.commit()?;
        Ok(session)
    }
}
