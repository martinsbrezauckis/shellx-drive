use chrono::Utc;
use rusqlite::{params, Transaction, TransactionBehavior};

use super::{
    prune_terminal_drop_upload_sessions_in_tx, row_to_drop_upload_record, DropUploadRecord,
};
use crate::{
    auth::{Actor, DriveCredential},
    error::ApiResult,
    model::Receipt,
    storage::{
        authorization, checked_stale_upload_cutoff, insert_receipt_rows, new_receipt, Storage,
    },
};

impl Storage {
    /// Authorize an administrative cleanup and snapshot possible stale
    /// sessions. Callers must take the matching stable Drop lock and then use
    /// the conditional reap method below before deleting any part file.
    pub fn stale_drop_upload_cleanup_candidates_authorized(
        &self,
        older_than_seconds: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(Vec<String>, Receipt)> {
        let cutoff = checked_stale_upload_cutoff(older_than_seconds)?;
        let receipt = new_receipt("drop.upload.cleanup", &actor.email, None);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let sessions = stale_drop_upload_session_ids_in_tx(&tx, &cutoff)?;
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((sessions, receipt))
    }

    /// Lists candidate stale Drop sessions. The result is not authority to
    /// delete their part files: callers must acquire the stable per-session
    /// lock and conditionally reap the exact ID.
    pub fn stale_drop_upload_session_ids(&self, older_than_seconds: i64) -> ApiResult<Vec<String>> {
        let cutoff = checked_stale_upload_cutoff(older_than_seconds)?;
        let conn = self.conn.lock().unwrap();
        stale_drop_upload_session_ids_in_connection(&conn, &cutoff)
    }

    /// Cancel one session only if it is still active and stale while the
    /// caller holds its matching Drop staging lock.
    pub fn reap_stale_drop_upload_session(
        &self,
        session_id: &str,
        older_than_seconds: i64,
    ) -> ApiResult<Option<DropUploadRecord>> {
        let cutoff = checked_stale_upload_cutoff(older_than_seconds)?;
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session = reap_stale_drop_upload_session_in_tx(&tx, session_id, &cutoff, &now)?;
        tx.commit()?;
        Ok(session)
    }

    /// Revalidate administrative authority while atomically checking that the
    /// Drop session remains stale. The matching filesystem lock is already
    /// held by the caller.
    pub fn reap_stale_drop_upload_session_authorized(
        &self,
        session_id: &str,
        older_than_seconds: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Option<DropUploadRecord>> {
        let cutoff = checked_stale_upload_cutoff(older_than_seconds)?;
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let session = reap_stale_drop_upload_session_in_tx(&tx, session_id, &cutoff, &now)?;
        tx.commit()?;
        Ok(session)
    }
}

fn stale_drop_upload_session_ids_in_tx(
    tx: &Transaction<'_>,
    cutoff: &str,
) -> ApiResult<Vec<String>> {
    let mut stmt = tx.prepare(
        "SELECT id FROM drop_upload_sessions
         WHERE status = 'active'
           AND julianday(updated_at) <= julianday(?1)",
    )?;
    let ids = stmt
        .query_map(params![cutoff], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(ids)
}

fn stale_drop_upload_session_ids_in_connection(
    conn: &rusqlite::Connection,
    cutoff: &str,
) -> ApiResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT id FROM drop_upload_sessions
         WHERE status = 'active'
           AND julianday(updated_at) <= julianday(?1)",
    )?;
    let ids = stmt
        .query_map(params![cutoff], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(ids)
}

fn reap_stale_drop_upload_session_in_tx(
    tx: &Transaction<'_>,
    session_id: &str,
    cutoff: &str,
    now: &str,
) -> ApiResult<Option<DropUploadRecord>> {
    if tx.execute(
        "UPDATE drop_upload_sessions
         SET status = 'canceled', canceled_at = ?1, updated_at = ?1,
             last_error_code = 'stale_cleanup'
         WHERE id = ?2
           AND status = 'active'
           AND julianday(updated_at) <= julianday(?3)",
        params![now, session_id, cutoff],
    )? == 0
    {
        return Ok(None);
    }
    let session = tx.query_row(
        "SELECT id, drop_id, workspace_id, client_fingerprint, transport_fingerprint, name, path,
                content_type, total_size, received_bytes, chunk_count,
                status, file_id, last_error_code, created_at, updated_at,
                completed_at, canceled_at
         FROM drop_upload_sessions WHERE id = ?1",
        params![session_id],
        row_to_drop_upload_record,
    )?;
    prune_terminal_drop_upload_sessions_in_tx(tx, &session.drop_id)?;
    Ok(Some(session))
}
