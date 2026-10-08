use rusqlite::{OptionalExtension, Transaction};
use serde_json::Value;

use crate::{
    error::{ApiError, ApiResult},
    model::BackupTable,
};

pub(super) fn current_access_generation(tx: &Transaction<'_>) -> ApiResult<i64> {
    let generation = tx
        .query_row(
            "SELECT generation FROM human_item_access_generation WHERE id = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    generation
        .filter(|value| *value >= 0)
        .ok_or_else(invalid_generation)
}

/// The archive's generation is validated as data but is never restored as
/// authority. Advance the live epoch exactly once after all continuity rows
/// have been reconciled so every pre-restore capability snapshot is stale.
pub(super) fn finalize_access_generation(
    tx: &Transaction<'_>,
    live_generation: i64,
    archived_generation: Option<i64>,
    sharing_tables_omitted: bool,
) -> ApiResult<()> {
    match (sharing_tables_omitted, archived_generation) {
        (true, None) | (false, Some(_)) => {}
        _ => return Err(invalid_generation()),
    }
    let generation = live_generation
        .checked_add(1)
        .ok_or_else(invalid_generation)?;
    tx.execute(
        "INSERT INTO human_item_access_generation (id, generation) VALUES (1, ?1)
         ON CONFLICT(id) DO UPDATE SET generation = excluded.generation",
        [generation],
    )?;
    let restored = tx
        .query_row(
            "SELECT generation FROM human_item_access_generation WHERE id = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if restored != Some(generation) {
        return Err(invalid_generation());
    }
    Ok(())
}

pub(super) fn legacy_access_generation(tables: &[BackupTable]) -> ApiResult<Option<i64>> {
    let Some(table) = tables
        .iter()
        .find(|table| table.name == "human_item_access_generation")
    else {
        return Ok(None);
    };
    if table.rows.len() != 1 {
        return Err(invalid_generation());
    }
    generation_from_row(&table.columns, &table.rows[0]).map(Some)
}

pub(super) fn record_v2_access_generation(
    columns: &[String],
    row: &[Value],
    archived_generation: &mut Option<i64>,
) -> ApiResult<()> {
    if archived_generation.is_some() {
        return Err(invalid_generation());
    }
    *archived_generation = Some(generation_from_row(columns, row)?);
    Ok(())
}

fn generation_from_row(columns: &[String], row: &[Value]) -> ApiResult<i64> {
    if columns != ["id", "generation"] || row.len() != 2 {
        return Err(invalid_generation());
    }
    let id = row[0].as_i64();
    let generation = row[1].as_i64();
    match (id, generation) {
        (Some(1), Some(generation)) if generation >= 0 => Ok(generation),
        _ => Err(invalid_generation()),
    }
}

fn invalid_generation() -> ApiError {
    ApiError::Validation(
        "restored human item access generation must contain exactly one canonical row".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::generation_from_row;

    #[test]
    fn rejects_noncanonical_access_generation_rows() {
        let columns = ["id".to_string(), "generation".to_string()];
        for row in [
            vec![json!(0), json!(1)],
            vec![json!(1), json!(-1)],
            vec![json!(1)],
        ] {
            assert!(generation_from_row(&columns, &row).is_err());
        }
    }
}
