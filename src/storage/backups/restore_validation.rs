use chrono::{DateTime, Duration, Utc};
use rusqlite::{OptionalExtension, Transaction};

use crate::{
    backup_v2::V2BlobDescriptor,
    error::{ApiError, ApiResult},
    model::BackupTable,
};

use super::{restore_accounting, restore_file_metadata, restore_topology};

pub(super) trait VerifiedBlob {
    fn hash(&self) -> &str;
    fn byte_length(&self) -> u64;
}

impl VerifiedBlob for V2BlobDescriptor {
    fn hash(&self) -> &str {
        &self.hash
    }

    fn byte_length(&self) -> u64 {
        self.byte_length
    }
}

impl VerifiedBlob for (String, u64) {
    fn hash(&self) -> &str {
        &self.0
    }

    fn byte_length(&self) -> u64 {
        self.1
    }
}

pub(super) fn validate_legacy_in_tx(
    tx: &Transaction<'_>,
    tables: &[BackupTable],
    catalog: &[(String, u64)],
) -> ApiResult<()> {
    let reconcile_legacy_cover_bytes = tables
        .iter()
        .find(|table| table.name == "files")
        .is_some_and(|table| !table.columns.iter().any(|column| column == "cover_bytes"));
    validate_in_tx(tx, catalog, reconcile_legacy_cover_bytes)
}

pub(super) fn validate_in_tx<T: VerifiedBlob>(
    tx: &Transaction<'_>,
    catalog: &[T],
    reconcile_legacy_cover_bytes: bool,
) -> ApiResult<()> {
    if catalog
        .windows(2)
        .any(|pair| pair[0].hash() >= pair[1].hash())
    {
        return Err(ApiError::Validation(
            "restored blob catalog is duplicate or out of order".to_string(),
        ));
    }
    validate_upload_session_ids_in_tx(tx)?;
    validate_upload_sessions_in_tx(tx)?;
    restore_topology::validate_in_tx(tx)?;
    restore_file_metadata::validate_in_tx(tx)?;
    restore_accounting::validate_in_tx(tx, catalog, reconcile_legacy_cover_bytes)
}

fn validate_upload_session_ids_in_tx(tx: &Transaction<'_>) -> ApiResult<()> {
    let mut statement = tx.prepare("SELECT id FROM upload_sessions")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    for id in rows {
        crate::upload_ids::require_canonical(&id?)?;
    }
    Ok(())
}

pub(super) fn validate_upload_session_reservations_in_tx(tx: &Transaction<'_>) -> ApiResult<()> {
    let invalid = tx
        .query_row(
            "SELECT id FROM upload_sessions
             WHERE completed = 0 AND canceled = 0
               AND quota_reservation_bytes < CASE
                   WHEN COALESCE(total_size, received_bytes) > 0
                   THEN COALESCE(total_size, received_bytes) ELSE 1 END
             LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(id) = invalid {
        return Err(ApiError::Validation(format!(
            "restored upload session {id} has an invalid quota reservation"
        )));
    }
    Ok(())
}

fn validate_upload_sessions_in_tx(tx: &Transaction<'_>) -> ApiResult<()> {
    let mut statement = tx.prepare(
        "SELECT id, workspace_id, name, total_size, received_bytes, completed, canceled,
                file_id, created_at, updated_at, canceled_at, path, target_file_id,
                base_revision, quota_reservation_bytes
         FROM upload_sessions",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<i64>>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, String>(9)?,
            row.get::<_, Option<String>>(10)?,
            row.get::<_, Option<String>>(11)?,
            row.get::<_, Option<String>>(12)?,
            row.get::<_, Option<i64>>(13)?,
            row.get::<_, i64>(14)?,
        ))
    })?;
    let latest_active_timestamp = Utc::now() + Duration::minutes(5);
    for row in rows {
        let (
            id,
            workspace_id,
            name,
            total_size,
            received_bytes,
            completed,
            canceled,
            file_id,
            created_at,
            updated_at,
            canceled_at,
            path,
            target_file_id,
            base_revision,
            quota_reservation_bytes,
        ) = row?;
        crate::storage::validate_file_name(&name)?;
        if let Some(path) = path.as_deref() {
            crate::storage::normalize_relative_upload_path(path)?;
        }
        if !matches!(completed, 0 | 1)
            || !matches!(canceled, 0 | 1)
            || (completed == 1 && canceled == 1)
            || received_bytes < 0
            || quota_reservation_bytes < 0
            || target_file_id.is_some() != base_revision.is_some()
            || base_revision.is_some_and(|revision| revision < 0)
        {
            return Err(invalid_upload_session(&id));
        }
        let created_at = DateTime::parse_from_rfc3339(&created_at)
            .map_err(|_| invalid_upload_session(&id))?
            .with_timezone(&Utc);
        let updated_at = DateTime::parse_from_rfc3339(&updated_at)
            .map_err(|_| invalid_upload_session(&id))?
            .with_timezone(&Utc);
        if updated_at < created_at {
            return Err(invalid_upload_session(&id));
        }
        let active = completed == 0 && canceled == 0;
        if active {
            if total_size.is_some_and(|total_size| total_size < 0 || received_bytes > total_size)
                || file_id.is_some()
                || canceled_at.is_some()
                || updated_at > latest_active_timestamp
            {
                return Err(invalid_upload_session(&id));
            }
            if let Some(target_file_id) = target_file_id.as_deref() {
                let target_exists = tx.query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM files
                         WHERE id = ?1 AND workspace_id = ?2 AND kind = 'file' AND trashed = 0
                     )",
                    rusqlite::params![target_file_id, workspace_id],
                    |target| target.get::<_, bool>(0),
                )?;
                if !target_exists {
                    return Err(invalid_upload_session(&id));
                }
            }
        }
    }
    Ok(())
}

fn invalid_upload_session(id: &str) -> ApiError {
    ApiError::Validation(format!(
        "restored upload session {id} violates live upload invariants"
    ))
}
