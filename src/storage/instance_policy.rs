use crate::{
    error::{ApiError, ApiResult},
    model::{BackupPolicy, SandboxProfile},
};

pub(crate) const MAX_BACKUP_RETENTION_COUNT: i64 = 10_000;
const MAX_SANDBOX_PATHS: usize = 256;
const MAX_SANDBOX_VALUE_BYTES: usize = 1_024;
const MAX_SYSTEMD_IDENTITY_BYTES: usize = 256;

pub(crate) fn validate_backup_schedule(schedule: &str) -> ApiResult<String> {
    let schedule = schedule.trim().to_ascii_lowercase();
    if matches!(schedule.as_str(), "manual" | "hourly" | "daily" | "weekly") {
        Ok(schedule)
    } else {
        Err(ApiError::Validation(
            "schedule must be manual, hourly, daily, or weekly".to_string(),
        ))
    }
}

pub(crate) fn validate_backup_retention_count(retention_count: i64) -> ApiResult<i64> {
    if !(1..=MAX_BACKUP_RETENTION_COUNT).contains(&retention_count) {
        return Err(ApiError::Validation(format!(
            "retention_count must be between 1 and {MAX_BACKUP_RETENTION_COUNT}"
        )));
    }
    Ok(retention_count)
}

pub(crate) fn ensure_valid_backup_policy(policy: &BackupPolicy) -> ApiResult<()> {
    let schedule = validate_backup_schedule(&policy.schedule)?;
    if schedule != policy.schedule {
        return Err(ApiError::Validation(
            "stored backup schedule is not canonical".to_string(),
        ));
    }
    validate_backup_retention_count(policy.retention_count)?;
    Ok(())
}

pub(crate) fn validate_sandbox_path(field: &str, value: &str) -> ApiResult<String> {
    let value = validate_sandbox_command_value(field, value)?;
    if !value.starts_with('/') || value.contains('%') {
        return Err(ApiError::Validation(format!(
            "{field} must be an absolute path without systemd specifiers"
        )));
    }
    Ok(value)
}

pub(crate) fn validate_sandbox_command_value(field: &str, value: &str) -> ApiResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_SANDBOX_VALUE_BYTES {
        return Err(ApiError::Validation(format!(
            "{field} must be between 1 and {MAX_SANDBOX_VALUE_BYTES} bytes"
        )));
    }
    let has_unsafe_character = trimmed.chars().any(|ch| {
        ch.is_control()
            || ch.is_whitespace()
            || matches!(
                ch,
                ';' | '|'
                    | '&'
                    | '`'
                    | '$'
                    | '<'
                    | '>'
                    | '"'
                    | '\''
                    | '\\'
                    | '('
                    | ')'
                    | '*'
                    | '?'
                    | '['
                    | ']'
                    | '{'
                    | '}'
            )
    });
    if has_unsafe_character {
        return Err(ApiError::Validation(format!(
            "{field} must not contain whitespace or shell metacharacters"
        )));
    }
    Ok(trimmed.to_string())
}

fn validate_systemd_identity(field: &str, value: &str) -> ApiResult<String> {
    let value = validate_sandbox_command_value(field, value)?;
    if value.len() > MAX_SYSTEMD_IDENTITY_BYTES || value.contains('%') {
        return Err(ApiError::Validation(format!(
            "{field} is too long or contains a systemd specifier"
        )));
    }
    Ok(value)
}

pub(crate) fn ensure_valid_sandbox_profile(profile: &SandboxProfile) -> ApiResult<()> {
    if profile.id != "default" {
        return Err(ApiError::Validation(
            "sandbox profile id must be default".to_string(),
        ));
    }
    if !matches!(profile.mode.as_str(), "strict" | "local-dev") {
        return Err(ApiError::Validation(
            "sandbox mode must be strict or local-dev".to_string(),
        ));
    }
    ensure_canonical(
        "sandbox data_dir",
        &profile.data_dir,
        validate_sandbox_path("sandbox data_dir", &profile.data_dir)?,
    )?;
    ensure_canonical(
        "sandbox bind",
        &profile.bind,
        validate_sandbox_command_value("sandbox bind", &profile.bind)?,
    )?;
    ensure_canonical(
        "sandbox service_user",
        &profile.service_user,
        validate_systemd_identity("sandbox service_user", &profile.service_user)?,
    )?;
    ensure_canonical(
        "sandbox service_group",
        &profile.service_group,
        validate_systemd_identity("sandbox service_group", &profile.service_group)?,
    )?;
    validate_sandbox_paths("sandbox read_write_paths", &profile.read_write_paths)?;
    validate_sandbox_paths("sandbox read_only_paths", &profile.read_only_paths)?;
    ensure_canonical(
        "sandbox network_policy",
        &profile.network_policy,
        validate_sandbox_command_value("sandbox network_policy", &profile.network_policy)?,
    )?;
    Ok(())
}

fn validate_sandbox_paths(field: &str, paths: &[String]) -> ApiResult<()> {
    if paths.len() > MAX_SANDBOX_PATHS {
        return Err(ApiError::Validation(format!(
            "{field} supports at most {MAX_SANDBOX_PATHS} paths"
        )));
    }
    for path in paths {
        ensure_canonical(field, path, validate_sandbox_path(field, path)?)?;
    }
    Ok(())
}

fn ensure_canonical(field: &str, original: &str, validated: String) -> ApiResult<()> {
    if original != validated {
        return Err(ApiError::Validation(format!(
            "stored {field} value is not canonical"
        )));
    }
    Ok(())
}
