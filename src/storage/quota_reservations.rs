use rusqlite::{params, OptionalExtension, Transaction};

use crate::error::{ApiError, ApiResult};

use super::retained_revision_quota_bytes;

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct ReservationExclusions<'a> {
    pub upload_session_id: Option<&'a str>,
    pub drop_upload_session_id: Option<&'a str>,
}

/// Enforce the configured workspace quota while reserving capacity across both
/// authenticated resumable uploads and public Drop uploads. Callers must use an
/// IMMEDIATE transaction so admission, reservation, and finalization serialize.
pub(super) fn enforce_workspace_quota_with_reservations(
    tx: &Transaction<'_>,
    workspace_id: &str,
    additional_bytes: i64,
    exclusions: ReservationExclusions<'_>,
) -> ApiResult<()> {
    if additional_bytes < 0 {
        return Err(ApiError::Validation(
            "workspace quota reservation must not be negative".to_string(),
        ));
    }

    let quota_bytes = tx
        .query_row(
            "SELECT quota_bytes FROM workspace_policies WHERE workspace_id = ?1",
            params![workspace_id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten();
    let Some(quota_bytes) = quota_bytes else {
        return Ok(());
    };

    let current_file_bytes: i64 = tx.query_row(
        "SELECT COALESCE(SUM(
                CASE WHEN content_bytes > 0 THEN content_bytes ELSE 1 END
                + CASE WHEN cover_bytes > 0 THEN cover_bytes ELSE 0 END
            ), 0)
         FROM files
         WHERE workspace_id = ?1",
        params![workspace_id],
        |row| row.get(0),
    )?;
    let retained_revision_bytes = retained_revision_quota_bytes(tx, workspace_id)?;
    let upload_reserved: i64 = tx.query_row(
        "SELECT COALESCE(SUM(CASE
                WHEN quota_reservation_bytes > 0 THEN quota_reservation_bytes ELSE 1 END), 0)
         FROM upload_sessions
         WHERE workspace_id = ?1 AND completed = 0 AND canceled = 0
           AND (?2 IS NULL OR id != ?2)",
        params![workspace_id, exclusions.upload_session_id],
        |row| row.get(0),
    )?;
    let drop_reserved: i64 = tx.query_row(
        "SELECT COALESCE(SUM(CASE
                WHEN total_size > 0 THEN total_size ELSE 1 END), 0)
         FROM drop_upload_sessions
         WHERE workspace_id = ?1 AND status = 'active'
           AND (?2 IS NULL OR id != ?2)",
        params![workspace_id, exclusions.drop_upload_session_id],
        |row| row.get(0),
    )?;
    let projected = current_file_bytes
        .checked_add(retained_revision_bytes)
        .and_then(|value| value.checked_add(upload_reserved))
        .and_then(|value| value.checked_add(drop_reserved))
        .and_then(|value| value.checked_add(additional_bytes))
        .ok_or_else(|| ApiError::Validation("workspace quota usage overflow".to_string()))?;
    if projected > quota_bytes {
        return Err(ApiError::Validation(format!(
            "quota exceeded: {projected} bytes including active upload reservations would exceed workspace quota {quota_bytes} bytes"
        )));
    }
    Ok(())
}
