use rusqlite::{params, OptionalExtension, Transaction};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    error::{ApiError, ApiResult},
    model::DriveFile,
};

use super::super::auxiliary_storage::{
    FileMetadataStorageProjection, WorkspaceAuxiliaryStorageDelta,
};
use super::super::{auxiliary_storage, enforce_quota_in_txn};

/// Replace the occupied canonical destination with the selected source's
/// current body and metadata. The source remains a retained item; no grants,
/// shares, or revision rows are moved between the two stable file IDs.
pub(in crate::storage) fn replace_source_at_destination_in_tx(
    tx: &Transaction<'_>,
    source: &DriveFile,
    target: &DriveFile,
    requested_labels: Option<&Vec<String>>,
    requested_custom_metadata: Option<&Value>,
    updated_at: &str,
) -> ApiResult<DriveFile> {
    let source_metadata = metadata_in_tx(tx, &source.id)?;
    let labels = match requested_labels {
        Some(labels) => labels.clone(),
        None => serde_json::from_str(&source_metadata.0).map_err(|error| {
            ApiError::Validation(format!("stored metadata labels are invalid: {error}"))
        })?,
    };
    let custom_metadata = match requested_custom_metadata {
        Some(metadata) => metadata.clone(),
        None => serde_json::from_str(&source_metadata.1).map_err(|error| {
            ApiError::Validation(format!("stored custom metadata is invalid: {error}"))
        })?,
    };
    let metadata = auxiliary_storage::project_file_metadata_storage(labels, &custom_metadata)?;
    ensure_metadata_admission_in_tx(tx, target, &metadata)?;

    let quota_bytes = tx
        .query_row(
            "SELECT quota_bytes FROM workspace_policies WHERE workspace_id = ?1",
            params![&target.workspace_id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten();
    let content_bytes = source.size_bytes.unwrap_or(0);
    if let Some(quota_bytes) = quota_bytes {
        // The current target body becomes a retained revision while the source
        // remains retained too, so admission must charge the incoming body.
        enforce_quota_in_txn(
            tx,
            quota_bytes,
            &target.workspace_id,
            Some(&target.id),
            content_bytes,
        )?;
    }

    let next_source_revision = source
        .revision
        .checked_add(1)
        .ok_or_else(|| ApiError::Validation("file revision overflow".to_string()))?;
    if tx.execute(
        "UPDATE files
         SET revision = ?1, trashed = 1, trashed_at = ?2, updated_at = ?2
         WHERE id = ?3 AND revision = ?4 AND trashed = 0",
        params![
            next_source_revision,
            updated_at,
            &source.id,
            source.revision
        ],
    )? != 1
    {
        return Err(ApiError::Conflict);
    }
    let next_target_revision = target
        .revision
        .checked_add(1)
        .ok_or_else(|| ApiError::Validation("file revision overflow".to_string()))?;
    if tx.execute(
        "UPDATE files
         SET revision = ?1, content_hash = ?2, content_bytes = ?3, updated_at = ?4
         WHERE id = ?5 AND revision = ?6 AND trashed = 0",
        params![
            next_target_revision,
            &source.content_hash,
            content_bytes,
            updated_at,
            &target.id,
            target.revision,
        ],
    )? != 1
    {
        return Err(ApiError::Conflict);
    }
    tx.execute(
        "INSERT INTO file_revisions
            (id, file_id, revision, content_hash, content_bytes, created_at, conflict_of_revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
        params![
            Uuid::now_v7().to_string(),
            &target.id,
            next_target_revision,
            &source.content_hash,
            content_bytes,
            updated_at,
        ],
    )?;
    tx.execute(
        "INSERT INTO file_metadata (file_id, labels_json, custom_json, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(file_id) DO UPDATE SET
            labels_json = excluded.labels_json,
            custom_json = excluded.custom_json,
            updated_at = excluded.updated_at",
        params![
            &target.id,
            metadata.labels_json,
            metadata.custom_json,
            updated_at,
        ],
    )?;
    tx.execute(
        "DELETE FROM mobile_offline_files WHERE file_id = ?1",
        params![&source.id],
    )?;

    let mut replaced = target.clone();
    replaced.revision = next_target_revision;
    replaced.content_hash = source.content_hash.clone();
    replaced.size_bytes = Some(content_bytes);
    replaced.updated_at = updated_at.to_string();
    Ok(replaced)
}

fn metadata_in_tx(tx: &Transaction<'_>, file_id: &str) -> ApiResult<(String, String)> {
    Ok(tx
        .query_row(
            "SELECT labels_json, custom_json FROM file_metadata WHERE file_id = ?1",
            params![file_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .unwrap_or_else(|| ("[]".to_string(), "{}".to_string())))
}

fn ensure_metadata_admission_in_tx(
    tx: &Transaction<'_>,
    target: &DriveFile,
    metadata: &FileMetadataStorageProjection,
) -> ApiResult<()> {
    let previous = metadata_in_tx(tx, &target.id)?;
    let prior_usage =
        auxiliary_storage::project_raw_file_metadata_storage_usage(&previous.0, &previous.1)?;
    let previous_projection_bytes = tx
        .query_row(
            "SELECT projection_bytes FROM workspace_auxiliary_metadata_fts_projection WHERE file_id = ?1",
            params![&target.id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(4);
    let delta = metadata
        .usage
        .checked_difference(WorkspaceAuxiliaryStorageDelta {
            file_metadata_bytes: prior_usage.file_metadata_bytes,
            metadata_fts_projection_bytes: previous_projection_bytes,
            ..WorkspaceAuxiliaryStorageDelta::default()
        })?;
    auxiliary_storage::ensure_workspace_auxiliary_storage_delta_fits_in_tx(
        tx,
        &target.workspace_id,
        delta,
    )?;
    Ok(())
}
