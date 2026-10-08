use rusqlite::Transaction;

use crate::{
    error::{ApiError, ApiResult},
    storage::validate_file_name,
};

/// Ensure every persisted file name can be restored verbatim. This gate is
/// shared by backup generation and restore so a legacy malformed row cannot
/// produce an archive that the same build would reject during recovery.
pub(super) fn validate_canonical_file_names_in_tx(tx: &Transaction<'_>) -> ApiResult<()> {
    let mut statement = tx.prepare("SELECT id, name FROM files ORDER BY id")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (id, name) = row?;
        let canonical = validate_file_name(&name).map_err(|error| {
            ApiError::Validation(format!("file {id} has an invalid name: {error}"))
        })?;
        if canonical != name {
            return Err(ApiError::Validation(format!(
                "file {id} has a non-canonical name"
            )));
        }
    }
    Ok(())
}
