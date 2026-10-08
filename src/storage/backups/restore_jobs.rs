use rusqlite::Transaction;
use serde_json::Value;

use crate::{
    error::{ApiError, ApiResult},
    storage::background_jobs,
};

pub(super) fn admit_row(tx: &Transaction<'_>, columns: &[String], row: &[Value]) -> ApiResult<()> {
    let required_text = |name: &str| -> ApiResult<&str> {
        let index = columns
            .iter()
            .position(|column| column == name)
            .ok_or_else(|| ApiError::Validation(format!("background_jobs lacks {name}")))?;
        row.get(index)
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::Validation(format!("background_jobs {name} is invalid")))
    };
    let kind = required_text("kind")?;
    let status = required_text("status")?;
    if status != "queued" || !matches!(kind, "search_index" | "preview_text") {
        return Ok(());
    }
    let _ = background_jobs::admit_restored_queued_job_in_tx(
        tx,
        kind,
        status,
        required_text("workspace_id")?,
        required_text("file_id")?,
    )?;
    Ok(())
}
