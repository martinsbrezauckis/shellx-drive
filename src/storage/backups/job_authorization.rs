use chrono::Utc;
use rusqlite::{params, OptionalExtension};

use crate::{
    auth::{Actor, AuthMode, DriveCredential},
    error::{ApiError, ApiResult},
};

use super::super::authorization;

/// Persist a durable, non-secret description of the source authority for
/// queued administrator work. Delegated credentials retain their own token
/// id so a later revoke or role loss stops work before it begins.
pub(super) fn queued_authority_metadata<'a>(
    authorization_context: Option<(&Actor, &'a DriveCredential)>,
    operator_credential_generation: &'a str,
) -> ApiResult<(Option<&'static str>, Option<&'a str>, Option<&'a str>)> {
    match authorization_context {
        Some((_, DriveCredential::Operator)) => {
            Ok((Some("operator"), None, Some(operator_credential_generation)))
        }
        Some((_, DriveCredential::UserSession(id))) => Ok((
            Some("user_session"),
            Some(id.as_str()),
            Some(operator_credential_generation),
        )),
        Some((_, DriveCredential::DelegatedAgentToken(id))) => {
            Ok((Some("delegated_agent"), Some(id.as_str()), None))
        }
        Some((_, DriveCredential::AppToken(_))) => Err(ApiError::Forbidden),
        None => Ok((Some("system_scheduled"), None, None)),
    }
}

pub(super) fn ensure_job_authorized(
    tx: &rusqlite::Transaction<'_>,
    job_id: &str,
    operator_credential_generation: &str,
) -> ApiResult<()> {
    let (email, credential_kind, credential_id, credential_generation) = tx
        .query_row(
            "SELECT actor, source_credential_kind, source_credential_id,
                    source_credential_generation
             FROM backup_jobs WHERE id = ?1",
            params![job_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(ApiError::Forbidden)?;
    if matches!(credential_kind.as_deref(), Some("system_scheduled"))
        && credential_id.is_none()
        && credential_generation.is_none()
    {
        return Ok(());
    }
    let credential = match credential_kind.as_deref() {
        Some("operator")
            if credential_id.is_none()
                && credential_generation.as_deref() == Some(operator_credential_generation) =>
        {
            DriveCredential::Operator
        }
        Some("user_session")
            if credential_generation.as_deref() == Some(operator_credential_generation) =>
        {
            DriveCredential::UserSession(credential_id.ok_or(ApiError::Forbidden)?)
        }
        Some("delegated_agent") if credential_generation.is_none() => {
            DriveCredential::DelegatedAgentToken(credential_id.ok_or(ApiError::Forbidden)?)
        }
        _ => return Err(ApiError::Forbidden),
    };
    let actor = Actor {
        email,
        is_admin: true,
        auth_mode: match &credential {
            DriveCredential::Operator => AuthMode::Operator,
            DriveCredential::UserSession(_) => AuthMode::LocalAccount,
            DriveCredential::DelegatedAgentToken(_) => AuthMode::DelegatedAgent,
            DriveCredential::AppToken(_) => unreachable!(),
        },
        allowed_workspace_ids: None,
    };
    authorization::ensure_admin_authorized(tx, &actor, &credential)
}

pub(super) fn fail_stale_jobs(
    tx: &rusqlite::Transaction<'_>,
    operator_credential_generation: &str,
) -> ApiResult<usize> {
    let now = Utc::now().to_rfc3339();
    Ok(tx.execute(
        "UPDATE backup_jobs
         SET status = 'failed',
             phase = CASE
               WHEN source_credential_kind IS NULL
                AND source_credential_id IS NULL
                AND source_credential_generation IS NULL
               THEN 'authority_unbound'
               WHEN source_credential_kind IN ('operator', 'user_session')
               THEN 'credential_rotated'
               ELSE 'authority_invalid'
             END,
             last_error = CASE
               WHEN source_credential_kind IS NULL
                AND source_credential_id IS NULL
                AND source_credential_generation IS NULL
               THEN 'queued work has no explicit authority class'
               WHEN source_credential_kind IN ('operator', 'user_session')
               THEN 'credential generation changed before queued work began'
               ELSE 'queued work has an invalid authority binding'
             END,
             updated_at = ?1, finished_at = ?1
         WHERE status = 'queued' AND (
           (source_credential_kind IS NULL
            AND source_credential_id IS NULL
            AND source_credential_generation IS NULL)
           OR (source_credential_kind = 'operator' AND (
                 source_credential_id IS NOT NULL
                 OR source_credential_generation IS NULL
                 OR source_credential_generation <> ?2))
           OR (source_credential_kind = 'user_session' AND (
                 source_credential_id IS NULL
                 OR source_credential_generation IS NULL
                 OR source_credential_generation <> ?2))
           OR (source_credential_kind = 'delegated_agent' AND (
                 source_credential_id IS NULL
                 OR source_credential_generation IS NOT NULL))
           OR (source_credential_kind = 'system_scheduled' AND (
                 source_credential_id IS NOT NULL
                 OR source_credential_generation IS NOT NULL))
           OR source_credential_kind IS NULL
           OR source_credential_kind NOT IN (
                 'operator', 'user_session', 'delegated_agent', 'system_scheduled')
         )",
        params![now, operator_credential_generation],
    )?)
}
