use rusqlite::Connection;

use crate::{
    error::{ApiError, ApiResult},
    storage::auxiliary_storage::ensure_workspace_auxiliary_storage_delta_fits_in_tx,
};

use super::{persist_comment_fanout_in_tx, prepare_comment_fanout_in_tx, CommentFanoutNotice};

/// Deliver a delete notice opportunistically. A tombstone has already reduced
/// the primary body before this runs, so the savepoint confines every optional
/// delivery side effect (including inbox pruning) to the fanout itself.
pub(crate) fn try_persist_optional_delete_fanout_in_tx(
    conn: &Connection,
    workspace_id: &str,
    notice: CommentFanoutNotice<'_>,
) -> ApiResult<()> {
    conn.execute_batch("SAVEPOINT optional_comment_delete_fanout")?;
    let result = (|| {
        let fanout = prepare_comment_fanout_in_tx(conn, notice)?;
        ensure_workspace_auxiliary_storage_delta_fits_in_tx(conn, workspace_id, fanout.delta)?;
        persist_comment_fanout_in_tx(conn, fanout)
    })();

    match result {
        Ok(()) => {
            conn.execute_batch("RELEASE optional_comment_delete_fanout")?;
            Ok(())
        }
        Err(error) => {
            conn.execute_batch(
                "ROLLBACK TO optional_comment_delete_fanout; \
                 RELEASE optional_comment_delete_fanout",
            )?;
            if is_optional_fanout_capacity_error(&error) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

fn is_optional_fanout_capacity_error(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::PayloadTooLarge(_) | ApiError::TooManyRequests
    )
}
