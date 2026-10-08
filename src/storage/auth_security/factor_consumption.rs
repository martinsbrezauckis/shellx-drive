use rusqlite::{params, OptionalExtension};

use super::VerifiedLocalSecondFactor;
use crate::error::{ApiError, ApiResult};

pub(in crate::storage) fn consume_totp_counter_in_tx(
    tx: &rusqlite::Transaction<'_>,
    email: &str,
    counter: i64,
) -> ApiResult<()> {
    if tx.execute(
        "UPDATE auth_accounts SET totp_last_used_counter = ?2
         WHERE email = ?1 AND totp_enabled = 1 AND disabled_at IS NULL
           AND (totp_last_used_counter IS NULL OR totp_last_used_counter < ?2)",
        params![email, counter],
    )? != 1
    {
        return Err(ApiError::Unauthenticated);
    }
    Ok(())
}

pub(in crate::storage) fn consume_current_second_factor_in_tx(
    tx: &rusqlite::Transaction<'_>,
    email: &str,
    expected_security_version: i64,
    second_factor: VerifiedLocalSecondFactor,
) -> ApiResult<()> {
    let enabled = tx
        .query_row(
            "SELECT totp_enabled FROM auth_accounts
             WHERE email = ?1 AND disabled_at IS NULL AND security_version = ?2",
            params![email, expected_security_version],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(ApiError::Conflict)?
        != 0;
    match (enabled, second_factor) {
        (false, VerifiedLocalSecondFactor::NotRequired) => Ok(()),
        (true, VerifiedLocalSecondFactor::TotpCounter(counter)) => {
            consume_totp_counter_in_tx(tx, email, counter)
        }
        (true, VerifiedLocalSecondFactor::RecoveryCode(hash)) => {
            consume_recovery_code_in_tx(tx, email, &hash)
        }
        _ => Err(ApiError::Unauthenticated),
    }
}

pub(in crate::storage) fn consume_recovery_code_in_tx(
    tx: &rusqlite::Transaction<'_>,
    email: &str,
    hash: &str,
) -> ApiResult<()> {
    let encoded_before = tx
        .query_row(
            "SELECT recovery_code_hashes FROM auth_accounts
             WHERE email = ?1 AND totp_enabled = 1 AND disabled_at IS NULL",
            params![email],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(ApiError::Unauthenticated)?;
    let mut hashes = super::super::parse_recovery_hashes(&encoded_before);
    let Some(position) = hashes.iter().position(|stored| stored == hash) else {
        return Err(ApiError::Unauthenticated);
    };
    hashes.remove(position);
    let encoded = serde_json::to_string(&hashes).map_err(|error| {
        ApiError::Validation(format!("failed to encode recovery codes: {error}"))
    })?;
    if tx.execute(
        "UPDATE auth_accounts SET recovery_code_hashes = ?2
         WHERE email = ?1 AND recovery_code_hashes = ?3",
        params![email, encoded, encoded_before],
    )? != 1
    {
        return Err(ApiError::Unauthenticated);
    }
    Ok(())
}

pub(in crate::storage) fn totp_counter_for_enable(
    second_factor: VerifiedLocalSecondFactor,
) -> ApiResult<i64> {
    match second_factor {
        VerifiedLocalSecondFactor::TotpCounter(counter) => Ok(counter),
        _ => Err(ApiError::Unauthenticated),
    }
}
