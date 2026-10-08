use chrono::{DateTime, Datelike, Duration, Utc};

use crate::{
    error::{ApiError, ApiResult},
    model::WorkspacePolicy,
};

pub(crate) const MIN_PUBLIC_CAPABILITY_PASSWORD_CHARS: usize = 12;

/// Validate only newly supplied public-capability passwords. Existing hashes,
/// including legacy weak passwords, remain verifiable until an owner rotates
/// or removes the password.
pub(crate) fn validate_new_public_capability_password(password: &str) -> ApiResult<bool> {
    if password.is_empty() {
        return Ok(false);
    }
    if password.trim().is_empty() || password.chars().count() < MIN_PUBLIC_CAPABILITY_PASSWORD_CHARS
    {
        return Err(ApiError::Validation(format!(
            "share and drop passwords must be at least {MIN_PUBLIC_CAPABILITY_PASSWORD_CHARS} characters"
        )));
    }
    Ok(true)
}

pub(crate) fn validate_share_policy(
    policy: &WorkspacePolicy,
    password_required: bool,
    expires_in_seconds: i64,
) -> ApiResult<()> {
    validate_public_links_enabled(policy)?;
    if policy.link_password_required && !password_required {
        return Err(ApiError::Validation(
            "workspace policy: share password is required".to_string(),
        ));
    }
    validate_share_expiry(policy, expires_in_seconds)
}

pub(crate) fn validate_share_update_policy(
    policy: &WorkspacePolicy,
    password_required: Option<bool>,
    expires_in_seconds: Option<i64>,
) -> ApiResult<()> {
    validate_public_links_enabled(policy)?;
    if policy.link_password_required && password_required == Some(false) {
        return Err(ApiError::Validation(
            "workspace policy: share password is required".to_string(),
        ));
    }
    if let Some(expires_in_seconds) = expires_in_seconds {
        validate_share_expiry(policy, expires_in_seconds)?;
    }
    Ok(())
}

pub(crate) fn validate_drop_policy(
    policy: &WorkspacePolicy,
    password_required: bool,
    expires_in_seconds: i64,
) -> ApiResult<()> {
    validate_public_links_enabled(policy)?;
    if policy.drop_password_required && !password_required {
        return Err(ApiError::Validation(
            "workspace policy: drop password is required".to_string(),
        ));
    }
    validate_drop_expiry(policy, expires_in_seconds)
}

pub(crate) fn validate_drop_update_policy(
    policy: &WorkspacePolicy,
    password_required: Option<bool>,
    expires_in_seconds: Option<i64>,
) -> ApiResult<()> {
    validate_public_links_enabled(policy)?;
    if policy.drop_password_required && password_required == Some(false) {
        return Err(ApiError::Validation(
            "workspace policy: drop password is required".to_string(),
        ));
    }
    if let Some(expires_in_seconds) = expires_in_seconds {
        validate_drop_expiry(policy, expires_in_seconds)?;
    }
    Ok(())
}

fn validate_public_links_enabled(policy: &WorkspacePolicy) -> ApiResult<()> {
    if !policy.public_links_enabled {
        return Err(ApiError::Validation(
            "workspace policy: public links are disabled".to_string(),
        ));
    }
    Ok(())
}

fn validate_share_expiry(policy: &WorkspacePolicy, expires_in_seconds: i64) -> ApiResult<()> {
    if expires_in_seconds <= 0 && !policy.allow_never_expire {
        return Err(ApiError::Validation(
            "workspace policy: permanent share links are disabled".to_string(),
        ));
    }
    if expires_in_seconds > 0 && expires_in_seconds > policy.max_link_ttl_seconds {
        return Err(ApiError::Validation(
            "workspace policy: share ttl exceeds workspace policy".to_string(),
        ));
    }
    checked_share_expiry(Utc::now(), expires_in_seconds)?;
    Ok(())
}

/// Keep timestamps sortable as four-digit RFC 3339 years in SQLite, and
/// reject stored legacy values that Chrono cannot represent without panicking.
pub(crate) fn checked_share_expiry(now: DateTime<Utc>, seconds: i64) -> ApiResult<Option<String>> {
    if seconds <= 0 {
        return Ok(None);
    }
    let duration = Duration::try_seconds(seconds).ok_or_else(|| {
        ApiError::Validation("share ttl exceeds the supported date range".to_string())
    })?;
    let expires_at = now
        .checked_add_signed(duration)
        .filter(|date| (1..=9999).contains(&date.year()))
        .ok_or_else(|| {
            ApiError::Validation("share ttl exceeds the supported date range".to_string())
        })?;
    Ok(Some(expires_at.to_rfc3339()))
}

pub(crate) fn checked_retention_cutoff(now: DateTime<Utc>, days: i64) -> ApiResult<DateTime<Utc>> {
    if days < 0 {
        return Err(ApiError::Validation(
            "workspace retention days must not be negative".to_string(),
        ));
    }
    let duration = Duration::try_days(days).ok_or_else(|| {
        ApiError::Validation("workspace retention exceeds the supported date range".to_string())
    })?;
    now.checked_sub_signed(duration)
        .filter(|date| (1..=9999).contains(&date.year()))
        .ok_or_else(|| {
            ApiError::Validation("workspace retention exceeds the supported date range".to_string())
        })
}

fn validate_drop_expiry(policy: &WorkspacePolicy, expires_in_seconds: i64) -> ApiResult<()> {
    if expires_in_seconds <= 0 {
        return Err(ApiError::Validation(
            "workspace policy: drop ttl must be positive".to_string(),
        ));
    }
    if expires_in_seconds > policy.max_drop_ttl_seconds {
        return Err(ApiError::Validation(
            "workspace policy: drop ttl exceeds workspace policy".to_string(),
        ));
    }
    Ok(())
}
