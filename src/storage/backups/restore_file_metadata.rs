mod auxiliary_metadata;

use rusqlite::{OptionalExtension, Transaction};

use super::file_names::validate_canonical_file_names_in_tx;

use crate::{
    error::{ApiError, ApiResult},
    path_projection::MAX_FILE_TREE_PROJECTED_PATH_BYTES,
};

/// Valid trees can contain 10,000 255-byte names plus identifiers, hashes, and
/// timestamps. Eight MiB admits that canonical worst case while preventing a
/// restore from publishing attacker-sized response metadata.
const MAX_RESTORED_WORKSPACE_FILE_METADATA_BYTES: i64 = 8 * 1024 * 1024;

pub(super) fn validate_in_tx(tx: &Transaction<'_>) -> ApiResult<()> {
    validate_aggregate_metadata(tx)?;
    validate_projected_paths(tx)?;
    auxiliary_metadata::validate_bounded_metadata_in_tx(tx)?;
    validate_rows(tx)
}

fn validate_aggregate_metadata(tx: &Transaction<'_>) -> ApiResult<()> {
    let oversized = tx
        .query_row(
            "SELECT workspace_id
             FROM files
             GROUP BY workspace_id
             HAVING SUM(
                 LENGTH(CAST(id AS BLOB))
                 + LENGTH(CAST(workspace_id AS BLOB))
                 + COALESCE(LENGTH(CAST(parent_id AS BLOB)), 0)
                 + LENGTH(CAST(name AS BLOB))
                 + LENGTH(CAST(kind AS BLOB))
                 + LENGTH(CAST(revision AS BLOB))
                 + LENGTH(CAST(trashed AS BLOB))
                 + LENGTH(CAST(starred AS BLOB))
                 + COALESCE(LENGTH(CAST(content_hash AS BLOB)), 0)
                 + LENGTH(CAST(content_bytes AS BLOB))
                 + LENGTH(CAST(created_at AS BLOB))
                 + LENGTH(CAST(updated_at AS BLOB))
                 + COALESCE(LENGTH(CAST(cover_hash AS BLOB)), 0)
                 + LENGTH(CAST(cover_bytes AS BLOB))
                 + COALESCE(LENGTH(CAST(trashed_at AS BLOB)), 0)
                 + 64
             ) > ?1
             LIMIT 1",
            [MAX_RESTORED_WORKSPACE_FILE_METADATA_BYTES],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(workspace_id) = oversized {
        return Err(ApiError::PayloadTooLarge(format!(
            "restored workspace {workspace_id} file metadata exceeds the {}-byte aggregate limit",
            MAX_RESTORED_WORKSPACE_FILE_METADATA_BYTES
        )));
    }
    Ok(())
}

fn validate_projected_paths(tx: &Transaction<'_>) -> ApiResult<()> {
    let oversized = tx
        .query_row(
            "WITH RECURSIVE paths(id, workspace_id, path_bytes) AS (
                 SELECT id, workspace_id, LENGTH(CAST(name AS BLOB))
                 FROM files WHERE parent_id IS NULL
                 UNION ALL
                 SELECT child.id, child.workspace_id,
                        paths.path_bytes + 1 + LENGTH(CAST(child.name AS BLOB))
                 FROM files child
                 JOIN paths
                   ON child.parent_id = paths.id
                  AND child.workspace_id = paths.workspace_id
             ), totals AS (
                 SELECT workspace_id, SUM(path_bytes) AS total_bytes
                 FROM paths GROUP BY workspace_id
             )
             SELECT workspace_id FROM totals WHERE total_bytes > ?1 LIMIT 1",
            [i64::try_from(MAX_FILE_TREE_PROJECTED_PATH_BYTES).unwrap_or(i64::MAX)],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(workspace_id) = oversized {
        return Err(ApiError::PayloadTooLarge(format!(
            "restored workspace {workspace_id} path metadata exceeds the {}-byte aggregate limit",
            MAX_FILE_TREE_PROJECTED_PATH_BYTES
        )));
    }
    Ok(())
}

fn validate_rows(tx: &Transaction<'_>) -> ApiResult<()> {
    if let Some(id) = tx
        .query_row(
            "SELECT id FROM files
             WHERE kind NOT IN ('file', 'folder')
                OR revision < 1
                OR trashed NOT IN (0, 1)
                OR starred NOT IN (0, 1)
                OR (kind = 'folder' AND (content_hash IS NOT NULL OR content_bytes <> 0))
                OR (kind = 'file' AND (cover_hash IS NOT NULL OR cover_bytes <> 0))
             LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        return Err(ApiError::Validation(format!(
            "restored file {id} violates canonical file-row invariants"
        )));
    }

    validate_canonical_file_names_in_tx(tx)
}

#[cfg(test)]
mod auxiliary_metadata_tests;
#[cfg(test)]
mod tests;
