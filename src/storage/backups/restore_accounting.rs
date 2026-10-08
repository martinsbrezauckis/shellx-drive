use rusqlite::{params, Transaction};

use crate::error::{ApiError, ApiResult};

use super::restore_validation::VerifiedBlob;

const VALIDATION_BATCH_SIZE: i64 = 1_000;

/// Treat the verified blob catalog as the sole byte-length authority. Only the
/// documented pre-`cover_bytes` schema is reconciled from SQLite's zero default.
pub(super) fn validate_in_tx<T: VerifiedBlob>(
    tx: &Transaction<'_>,
    catalog: &[T],
    reconcile_legacy_cover_bytes: bool,
) -> ApiResult<()> {
    validate_column(
        tx,
        "files",
        "id",
        "content_hash",
        "content_bytes",
        catalog,
        false,
    )?;
    validate_column(
        tx,
        "file_revisions",
        "id",
        "content_hash",
        "content_bytes",
        catalog,
        false,
    )?;
    validate_column(
        tx,
        "file_previews",
        "file_id",
        "thumbnail_hash",
        "thumbnail_bytes",
        catalog,
        false,
    )?;
    validate_column(
        tx,
        "files",
        "id",
        "cover_hash",
        "cover_bytes",
        catalog,
        reconcile_legacy_cover_bytes,
    )
}

fn validate_column<T: VerifiedBlob>(
    tx: &Transaction<'_>,
    table: &str,
    id_column: &str,
    hash_column: &str,
    bytes_column: &str,
    catalog: &[T],
    reconcile: bool,
) -> ApiResult<()> {
    let mut after_id: Option<String> = None;
    loop {
        let rows = {
            let sql = format!(
                "SELECT {id_column}, {hash_column}, {bytes_column} FROM {table}
                 WHERE (?1 IS NULL OR {id_column} > ?1)
                 ORDER BY {id_column} ASC LIMIT ?2"
            );
            let mut statement = tx.prepare(&sql)?;
            let rows = statement.query_map(
                params![after_id.as_deref(), VALIDATION_BATCH_SIZE],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        if rows.is_empty() {
            return Ok(());
        }
        for (id, hash, stored_bytes) in &rows {
            let expected_bytes = match hash {
                Some(hash) => catalog
                    .binary_search_by(|item| item.hash().cmp(hash))
                    .ok()
                    .and_then(|index| catalog.get(index))
                    .ok_or_else(|| {
                        ApiError::Validation(format!(
                            "restored {table} row {id} references a blob absent from the verified catalog"
                        ))
                    })?
                    .byte_length()
                    .try_into()
                    .map_err(|_| {
                        ApiError::PayloadTooLarge(
                            "restored blob exceeds SQLite byte-length range".to_string(),
                        )
                    })?,
                None => 0,
            };
            if *stored_bytes == expected_bytes {
                continue;
            }
            if reconcile {
                let sql = format!("UPDATE {table} SET {bytes_column} = ?1 WHERE {id_column} = ?2");
                tx.execute(&sql, params![expected_bytes, id])?;
            } else {
                return Err(ApiError::Validation(format!(
                    "restored {table}.{bytes_column} for row {id} does not match the verified blob catalog"
                )));
            }
        }
        after_id = rows.last().map(|(id, _, _)| id.clone());
    }
}
