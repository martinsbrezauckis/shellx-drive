use rusqlite::{params, OptionalExtension};

use crate::error::ApiResult;

use super::{row_to_drop_record, DropRecord, Storage};

impl Storage {
    /// Keep terminal public authorization and proof creation under one DB lock.
    /// The callback must not perform further storage operations.
    pub(crate) fn with_current_drop_record<T>(
        &self,
        drop_id: &str,
        use_record: impl FnOnce(Option<DropRecord>) -> ApiResult<T>,
    ) -> ApiResult<T> {
        let conn = self.conn.lock().unwrap();
        let record = conn
            .query_row(
                "SELECT id, workspace_id, name, password_hash, expires_at, revoked, created_at,
                        upload_count, last_uploaded_at, inbox_file_id, password_required
                 FROM drops WHERE id = ?1 AND publication_pending = 0",
                params![drop_id],
                row_to_drop_record,
            )
            .optional()?;
        use_record(record)
    }
}
