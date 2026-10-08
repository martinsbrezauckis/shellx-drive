use rusqlite::Transaction;

use crate::{
    error::ApiResult, storage::auxiliary_storage::project_persisted_file_metadata_storage,
};

/// Backup metadata is an authority for the visible file record, but not for
/// derived FTS or auxiliary-ledger rows. Validate every restored row through
/// the normal bounded canonical projection before either derived structure is
/// rebuilt.
pub(super) fn validate_bounded_metadata_in_tx(tx: &Transaction<'_>) -> ApiResult<()> {
    let mut statement = tx.prepare("SELECT labels_json, custom_json FROM file_metadata")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (labels_json, custom_json) = row?;
        project_persisted_file_metadata_storage(&labels_json, &custom_json)?;
    }
    Ok(())
}
